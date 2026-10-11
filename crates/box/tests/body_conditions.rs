//! A body condition refines an allowed `http:request` through a real gateway
//! (docs/design/decisions.md#a-body-condition-is-a-declared-refinement).

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    CapabilitySet, CredentialCapability, MitmConfig, MitmHandle, MitmInterceptor,
};
use harness::{TlsUpstream, WorkloadClient};
use policy::{
    EgressPolicyInterceptor, GovernedBox, HttpBodyRoute, Operator, Policy, PolicyEngine, Principal,
};

const HOST: &str = "wiki.bound.test";
const REAL_SECRET: &str = "sk_live_body_conditions_4d2a";

fn env_locator(secret: &str) -> Locator {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "BODY_CONDITIONS_SECRET_{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // SAFETY: the name is unique to this call, so no other test reads or writes it.
    unsafe { std::env::set_var(&name, secret) };
    Locator::parse_uri(&format!("env://{name}")).expect("an env locator parses")
}

/// The documented fail-closed form (docs/user/policy/actions.md), with the coarse permits.
fn safe_policy(port: u16) -> String {
    format!(
        r#"permit(principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == "{HOST}" && context.input.port == {port} }};
permit(principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == "{HOST}" && context.input.port == {port} }};
@id("wiki_search_scope")
forbid (principal, action == wiki::Action::"http_body", resource)
when   {{ context.input.method == "POST" && context.input.path == "/rest/search" }}
unless {{ context.input.body_json && context.input has spaces &&
         ["eng", "docs"].containsAll(context.input.spaces) }};"#
    )
}

/// A box whose `wiki` route reads `spaces` from a request body, or no route at all.
struct BodyBox {
    upstream: TlsUpstream,
    handle: MitmHandle,
    phantom: String,
    _history: tempfile::TempDir,
}

fn body_box(with_route: bool) -> BodyBox {
    let upstream = TlsUpstream::start(HOST);
    let port = upstream.port();
    let pattern = || DestinationPattern::parse(&format!("{HOST}:{port}")).expect("a pattern");
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(
            pattern(),
            env_locator(REAL_SECRET),
            InjectMode::header("Bearer {}".to_string(), None).expect("a header placement"),
        ),
    ))
    .expect("the vault opens");
    let phantom = opened.phantoms()[0].token().to_string();
    let history = tempfile::tempdir().expect("a history directory");
    let route = HttpBodyRoute::new(
        "wiki",
        [(
            "spaces".to_string(),
            "/filter/spaces".to_string(),
            "set<string>".to_string(),
        )],
    )
    .expect("a valid route");
    // Without the route, the rule naming `wiki::Action::"http_body"` does not load, so the
    // opt-out box keeps only the coarse permits.
    let text = if with_route {
        safe_policy(port)
    } else {
        safe_policy(port)
            .split("@id")
            .next()
            .expect("the coarse permits")
            .to_string()
    };
    let engine = PolicyEngine::open_staged_with_body_routes(
        &Operator::unanchored(),
        vec![Policy {
            origin: PathBuf::from("body-conditions.dw"),
            text,
        }],
        if with_route { vec![route] } else { Vec::new() },
        &history.path().join("dogwood.redb"),
    )
    .expect("the policy opens");
    let interceptor = EgressPolicyInterceptor::into_handle(
        Arc::new(engine),
        Principal::agent(),
        GovernedBox::assigned("body-conditions"),
    );
    let capabilities = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(
            pattern(),
            Arc::new(opened.into_vault()),
        ))
        .build();
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(HOST.to_string(), "127.0.0.1".parse().expect("loopback"))],
        body_routes: if with_route {
            vec![(pattern(), "wiki".to_string())]
        } else {
            Vec::new()
        },
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, capabilities, interceptor).expect("the gateway starts");
    BodyBox {
        upstream,
        handle,
        phantom,
        _history: history,
    }
}

impl BodyBox {
    /// POST `body` to `path` with the phantom attached, and return the whole response.
    fn post(&self, path: &str, headers: &[(&str, &str)], body: &[u8]) -> String {
        let proxy_port = self.handle.port().expect("a TCP gateway has a port");
        let authorization = format!("Bearer {}", self.phantom);
        let mut all = vec![("Authorization", authorization.as_str())];
        all.extend_from_slice(headers);
        let mut client = WorkloadClient::connect(proxy_port, HOST, self.upstream.port());
        client.send_request("POST", path, &all, body);
        client.read_response()
    }

    fn status(&self, path: &str, headers: &[(&str, &str)], body: &[u8]) -> u16 {
        let response = self.post(path, headers, body);
        response
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("an HTTP status line: {response}"))
    }
}

#[test]
fn allowed_spaces_reach_the_upstream() {
    let wiki = body_box(true);
    assert_eq!(
        wiki.status(
            "/rest/search",
            &[],
            br#"{"filter":{"spaces":["eng","docs"]}}"#
        ),
        200
    );
    assert!(wiki.upstream.last_request().raw.contains("docs"));
}

#[test]
fn a_foreign_or_mixed_space_is_refused_before_the_upstream() {
    let wiki = body_box(true);
    for body in [
        &br#"{"filter":{"spaces":["secret"]}}"#[..],
        br#"{"filter":{"spaces":["eng","secret"]}}"#,
    ] {
        assert_eq!(wiki.status("/rest/search", &[], body), 403);
    }
    assert_eq!(
        wiki.upstream.request_count(),
        0,
        "nothing reached the upstream"
    );
}

#[test]
fn a_duplicate_key_smuggle_is_refused() {
    let wiki = body_box(true);
    assert_eq!(
        wiki.status(
            "/rest/search",
            &[],
            br#"{"filter":{"spaces":["eng"],"spaces":["secret"]}}"#
        ),
        403
    );
    assert_eq!(wiki.upstream.request_count(), 0);
}

#[test]
fn an_encoded_body_is_refused_on_the_scoped_path() {
    let wiki = body_box(true);
    assert_eq!(
        wiki.status(
            "/rest/search",
            &[("Content-Encoding", "gzip")],
            br#"{"filter":{"spaces":["eng"]}}"#
        ),
        403
    );
}

#[test]
fn a_non_json_upload_on_another_path_passes() {
    let wiki = body_box(true);
    assert_eq!(
        wiki.status(
            "/upload",
            &[("Content-Type", "application/octet-stream")],
            b"\x00\x01raw"
        ),
        200
    );
}

#[test]
fn a_refusal_is_marked_and_quotes_no_body_value() {
    let wiki = body_box(true);
    let response = wiki.post(
        "/rest/search",
        &[],
        br#"{"filter":{"spaces":["body-secret"]}}"#,
    );
    let (head, body) = response.split_once("\r\n\r\n").expect("an HTTP response");
    assert!(head.starts_with("HTTP/1.1 403 "), "{response}");
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("x-strands-box-egress: refused")),
        "{head}"
    );
    assert!(body.contains(r#"wiki::Action::"http_body""#), "{body}");
    assert!(!response.contains("body-secret"), "{response}");
    assert!(!response.contains(REAL_SECRET), "{response}");
}

#[test]
fn a_route_without_body_fields_is_unchanged() {
    let plain = body_box(false);
    assert_eq!(
        plain.status("/rest/search", &[], br#"{"filter":{"spaces":["secret"]}}"#),
        200
    );
}
