//! Operator-declared request-body fields for one egress route, and the strict extractor that
//! reads them (docs/design/decisions.md#a-body-condition-is-a-declared-refinement).

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::schema::mcp_action_namespace;

pub(crate) const HTTP_BODY_ACTION: &str = "http_body";
pub(crate) const BODY_PARSE_LIMIT: usize = 1024 * 1024;
const MAX_BODY_DEPTH: usize = 64;
const FIXED_FIELDS: [&str; 7] = [
    "host",
    "port",
    "method",
    "path",
    "body_bytes",
    "intercepted",
    "body_json",
];
const RESERVED_WORDS: [&str; 10] = [
    "true", "false", "if", "then", "else", "in", "is", "like", "has", "__cedar",
];

/// A refused `body.fields` declaration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpBodyError {
    /// The route declares no field, so it opts in to nothing.
    #[error("route `{route}` declares no body field")]
    NoFields {
        /// The egress route name.
        route: String,
    },
    /// A field name is not an identifier, is reserved, or repeats.
    #[error("route `{route}` body field `{name}`: {reason}")]
    FieldName {
        /// The egress route name.
        route: String,
        /// The refused field name.
        name: String,
        /// Why it is refused.
        reason: String,
    },
    /// A pointer is not an RFC 6901 JSON Pointer to a part of the document.
    #[error(
        "route `{route}` body field `{name}`: `{pointer}` is not a JSON Pointer (it starts with \
         `/`, and each `~` is followed by `0` or `1`)"
    )]
    Pointer {
        /// The egress route name.
        route: String,
        /// The field name.
        name: String,
        /// The refused pointer.
        pointer: String,
    },
    /// A type is not one of the five supported spellings.
    #[error(
        "route `{route}` body field `{name}`: unknown type `{kind}` (expected string, long, bool, \
         set<string>, or set<long>)"
    )]
    Type {
        /// The egress route name.
        route: String,
        /// The field name.
        name: String,
        /// The refused type spelling.
        kind: String,
    },
    /// The route name normalizes to the built-in `Box` namespace.
    #[error("route `{route}` normalizes to the reserved policy namespace `Box`")]
    ReservedNamespace {
        /// The egress route name.
        route: String,
    },
}

/// The type a declared field takes in `context.input`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBodyFieldType {
    /// A JSON string.
    String,
    /// A JSON integer in the i64 range.
    Long,
    /// A JSON boolean.
    Bool,
    /// An array of strings, or one string.
    SetString,
    /// An array of i64 integers, or one integer.
    SetLong,
}

impl HttpBodyFieldType {
    /// Parse the `box.toml` spelling.
    pub fn parse(s: &str) -> Result<Self, HttpBodyError> {
        match s {
            "string" => Ok(Self::String),
            "long" => Ok(Self::Long),
            "bool" => Ok(Self::Bool),
            "set<string>" => Ok(Self::SetString),
            "set<long>" => Ok(Self::SetLong),
            other => Err(HttpBodyError::Type {
                route: String::new(),
                name: String::new(),
                kind: other.into(),
            }),
        }
    }

    fn cedar(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::Long => "Long",
            Self::Bool => "Bool",
            Self::SetString => "Set<String>",
            Self::SetLong => "Set<Long>",
        }
    }

    /// The value at `found` as this type, or `None`.
    fn lower(self, found: &Value) -> Option<Value> {
        let scalar = |v: &Value| match self {
            Self::String | Self::SetString => v.is_string(),
            Self::Long | Self::SetLong => v.as_i64().is_some() && !v.is_f64(),
            Self::Bool => v.is_boolean(),
        };
        match self {
            Self::String | Self::Long | Self::Bool => scalar(found).then(|| found.clone()),
            Self::SetString | Self::SetLong => match found {
                Value::Array(items) => items.iter().all(scalar).then(|| found.clone()),
                other => scalar(other).then(|| Value::Array(vec![other.clone()])),
            },
        }
    }
}

/// One declared body field: the name policy reads, where it sits, and its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBodyField {
    name: String,
    pointer: String,
    kind: HttpBodyFieldType,
}

impl HttpBodyField {
    /// The attribute name under `context.input`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The RFC 6901 JSON Pointer into the body.
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// The declared type.
    pub fn kind(&self) -> HttpBodyFieldType {
        self.kind
    }
}

/// The body fields one egress route declares, and the policy namespace its action lives in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBodyRoute {
    route: String,
    namespace: String,
    fields: Vec<HttpBodyField>,
}

impl HttpBodyRoute {
    /// Validate a route's declaration. Each item is `(name, pointer, type)`.
    pub fn new(
        route: &str,
        fields: impl IntoIterator<Item = (String, String, String)>,
    ) -> Result<Self, HttpBodyError> {
        let fields: Vec<_> = fields.into_iter().collect();
        if fields.is_empty() {
            return Err(HttpBodyError::NoFields {
                route: route.into(),
            });
        }
        let namespace = mcp_action_namespace(route);
        if namespace == "Box" {
            return Err(HttpBodyError::ReservedNamespace {
                route: route.into(),
            });
        }
        let mut declared: Vec<HttpBodyField> = Vec::with_capacity(fields.len());
        for (name, pointer, kind) in fields {
            let refuse_name = |reason: &str| HttpBodyError::FieldName {
                route: route.into(),
                name: name.clone(),
                reason: reason.into(),
            };
            if !is_identifier(&name) {
                return Err(refuse_name("not an identifier ([A-Za-z_][A-Za-z0-9_]*)"));
            }
            if FIXED_FIELDS.contains(&name.as_str()) {
                return Err(refuse_name("names a field Box sets"));
            }
            if RESERVED_WORDS.contains(&name.as_str()) {
                return Err(refuse_name("is a policy-language reserved word"));
            }
            if declared.iter().any(|field| field.name == name) {
                return Err(refuse_name("repeated"));
            }
            if !is_pointer(&pointer) {
                return Err(HttpBodyError::Pointer {
                    route: route.into(),
                    name,
                    pointer,
                });
            }
            let kind = HttpBodyFieldType::parse(&kind).map_err(|_| HttpBodyError::Type {
                route: route.into(),
                name: name.clone(),
                kind,
            })?;
            declared.push(HttpBodyField {
                name,
                pointer,
                kind,
            });
        }
        Ok(Self {
            route: route.into(),
            namespace,
            fields: declared,
        })
    }

    /// The egress route name.
    pub fn route(&self) -> &str {
        &self.route
    }

    /// The policy namespace of the route's `http_body` action.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The declared fields, in declaration order.
    pub fn fields(&self) -> &[HttpBodyField] {
        &self.fields
    }

    /// Read the declared fields from `body`. The object always holds `body_json`; a field is
    /// present only when the body parsed strictly and the pointer found a value of its type.
    pub(crate) fn extract(&self, body: &[u8], encoded: bool) -> Value {
        let mut input = Map::new();
        let parsed = (!encoded && !body.is_empty() && body.len() <= BODY_PARSE_LIMIT)
            .then(|| strict_parse(body))
            .flatten();
        input.insert("body_json".into(), Value::Bool(parsed.is_some()));
        if let Some(document) = parsed {
            for field in &self.fields {
                if let Some(value) = document
                    .pointer(&field.pointer)
                    .and_then(|v| field.kind.lower(v))
                {
                    input.insert(field.name.clone(), value);
                }
            }
        }
        Value::Object(input)
    }
}

/// The route's action fragment: one `http_body` action whose input holds the
/// `http:request` fields, `body_json`, and each declared field as an optional attribute.
pub fn generate_http_body_schema(route: &HttpBodyRoute) -> String {
    let mut fields = String::from(
        "host: String, port: Long, method: String, path: String, body_bytes: Long, \
         intercepted: Bool, body_json: Bool",
    );
    for field in &route.fields {
        fields.push_str(&format!(", {}?: {}", field.name, field.kind.cedar()));
    }
    format!(
        "namespace {ns} {{\n    type HttpBodyInput = {{ {fields} }};\n    action \"{HTTP_BODY_ACTION}\" appliesTo {{\n        principal: [Box::Agent],\n        resource: [Box::Resource],\n        context: {{ input: HttpBodyInput, output?: Box::NetworkResponseOutput }}\n    }};\n}}\n",
        ns = route.namespace
    )
}

fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_pointer(pointer: &str) -> bool {
    let mut bytes = pointer.bytes();
    if bytes.next() != Some(b'/') {
        return false;
    }
    while let Some(b) = bytes.next() {
        if b == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

/// One strict JSON text: no duplicate key at any depth, nesting at most `MAX_BODY_DEPTH`.
fn strict_parse(body: &[u8]) -> Option<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = DepthSeed(0).deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    Some(value)
}

struct DepthSeed(usize);

impl<'de> DeserializeSeed<'de> for DepthSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor(self.0))
    }
}

struct StrictVisitor(usize);

impl StrictVisitor {
    fn nested<E: de::Error>(&self) -> Result<DepthSeed, E> {
        if self.0 + 1 > MAX_BODY_DEPTH {
            return Err(E::custom("nesting too deep"));
        }
        Ok(DepthSeed(self.0 + 1))
    }
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.into()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self.nested()?)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        // The depth check runs before the first key, so an empty object counts too.
        let seed = self.nested::<A::Error>()?;
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(DepthSeed(seed.0))?;
            if object.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate key"));
            }
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn wiki() -> HttpBodyRoute {
        HttpBodyRoute::new(
            "wiki",
            [
                (
                    "spaces".into(),
                    "/filter/spaces".into(),
                    "set<string>".into(),
                ),
                ("limit".into(), "/limit".into(), "long".into()),
                ("first".into(), "/filters/0/space".into(), "string".into()),
                ("odd".into(), "/a~1b/c~0d".into(), "bool".into()),
            ],
        )
        .expect("valid route")
    }

    #[test]
    fn a_strict_body_yields_typed_fields() {
        let input = wiki().extract(
            br#"{"filter":{"spaces":["eng","docs"]},"limit":5,
            "filters":[{"space":"eng"}],"a/b":{"c~d":true}}"#,
            false,
        );
        assert_eq!(
            input,
            json!({"body_json":true,"spaces":["eng","docs"],"limit":5,
            "first":"eng","odd":true})
        );
    }

    #[test]
    fn a_scalar_becomes_a_one_element_set_and_an_empty_array_an_empty_set() {
        assert_eq!(
            wiki().extract(br#"{"filter":{"spaces":"eng"}}"#, false),
            json!({"body_json":true,"spaces":["eng"]})
        );
        assert_eq!(
            wiki().extract(br#"{"filter":{"spaces":[]}}"#, false),
            json!({"body_json":true,"spaces":[]})
        );
    }

    #[test]
    fn a_wrong_type_or_mixed_array_or_float_leaves_the_field_absent() {
        assert_eq!(
            wiki().extract(br#"{"filter":{"spaces":["eng",1]},"limit":1.0}"#, false),
            json!({"body_json":true})
        );
        assert_eq!(
            wiki().extract(br#"{"limit":1e3}"#, false),
            json!({"body_json":true})
        );
    }

    #[test]
    fn a_duplicate_key_at_any_depth_refuses_the_parse() {
        let unparsed = json!({"body_json":false});
        assert_eq!(
            wiki().extract(
                br#"{"filter":{"spaces":["eng"],"spaces":["secret"]}}"#,
                false
            ),
            unparsed
        );
        assert_eq!(
            wiki().extract(br#"{"a":{"b":{"c":{"d":{"e":1,"e":2}}}}}"#, false),
            unparsed
        );
        assert_eq!(wiki().extract(br#"{"limit":1,"limit":2}"#, false), unparsed);
    }

    #[test]
    fn unparseable_bodies_set_body_json_false() {
        let unparsed = json!({"body_json":false});
        for body in [
            &b""[..],
            b"{",
            b"{\"limit\":1} x",
            b"\xEF\xBB\xBF{\"limit\":1}",
            b"{\"limit\":1,}",
            b"{/*c*/\"limit\":1}",
            b"limit=1",
        ] {
            assert_eq!(wiki().extract(body, false), unparsed, "{body:?}");
        }
        assert_eq!(wiki().extract(br#"{"limit":1}"#, true), unparsed, "encoded");
    }

    #[test]
    fn the_depth_limit_is_64() {
        let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert_eq!(
            wiki().extract(nest(64).as_bytes(), false),
            json!({"body_json":true})
        );
        assert_eq!(
            wiki().extract(nest(65).as_bytes(), false),
            json!({"body_json":false})
        );
    }

    #[test]
    fn the_parse_limit_is_one_mebibyte() {
        let pad = |total: usize| {
            let head = br#"{"limit":1,"p":""#;
            let tail = br#""}"#;
            let mut v = head.to_vec();
            v.resize(total - tail.len(), b'x');
            v.extend_from_slice(tail);
            v
        };
        assert_eq!(
            wiki().extract(&pad(BODY_PARSE_LIMIT), false),
            json!({"body_json":true,"limit":1})
        );
        assert_eq!(
            wiki().extract(&pad(BODY_PARSE_LIMIT + 1), false),
            json!({"body_json":false})
        );
    }

    #[test]
    fn declarations_are_validated() {
        let one = |n: &str, p: &str, t: &str| {
            HttpBodyRoute::new("wiki", [(n.into(), p.into(), t.into())])
        };
        assert!(matches!(
            HttpBodyRoute::new("wiki", Vec::<(String, String, String)>::new()),
            Err(HttpBodyError::NoFields { .. })
        ));
        for name in ["host", "body_json", "has", "9x", "a-b", ""] {
            assert!(
                matches!(
                    one(name, "/a", "string"),
                    Err(HttpBodyError::FieldName { .. })
                ),
                "{name}"
            );
        }
        for pointer in ["", "a", "/a~2", "/a~"] {
            assert!(
                matches!(
                    one("f", pointer, "string"),
                    Err(HttpBodyError::Pointer { .. })
                ),
                "{pointer}"
            );
        }
        assert!(matches!(
            one("f", "/a", "set<bool>"),
            Err(HttpBodyError::Type { .. })
        ));
        assert!(matches!(
            HttpBodyRoute::new("Box", [("f".into(), "/a".into(), "long".into())]),
            Err(HttpBodyError::ReservedNamespace { .. })
        ));
    }

    #[test]
    fn the_namespace_uses_the_mcp_normalization() {
        let r = HttpBodyRoute::new("9-wiki", [("f".into(), "/a".into(), "long".into())]).unwrap();
        assert_eq!(r.namespace(), "_9_wiki");
    }

    #[test]
    fn the_fragment_declares_one_optional_typed_action() {
        let fragment = generate_http_body_schema(&wiki());
        // Composes with the built-in schema and passes the MCP namespace guard.
        crate::mcp_schema::validate_unbound_mcp_schema(&fragment)
            .expect("fragment stays in its namespace");
        let (_, warnings) = cedar_policy::Schema::from_cedarschema_str(&format!(
            "{}\n{fragment}",
            crate::schema::SCHEMA_SRC
        ))
        .expect("fragment composes");
        assert_eq!(warnings.count(), 0, "fragment composes without warnings");
        for needle in [
            "namespace wiki",
            "action \"http_body\"",
            "spaces?: Set<String>",
            "limit?: Long",
            "body_json: Bool",
            "body_bytes: Long",
            "output?: Box::NetworkResponseOutput",
        ] {
            assert!(fragment.contains(needle), "missing {needle} in {fragment}");
        }
    }
}
