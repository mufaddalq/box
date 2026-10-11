//! The `http_body` refinement: declared fields, forbid-only semantics, and fail-closed parsing.

use std::path::PathBuf;

use policy::{
    Decision, GovernedBox, HttpBodyRoute, Operator, Policy, PolicyEngine, Principal, SchemaStage,
};

fn wiki() -> HttpBodyRoute {
    HttpBodyRoute::new(
        "wiki",
        [
            (
                "spaces".into(),
                "/filter/spaces".into(),
                "set<string>".into(),
            ),
            ("space".into(), "/space".into(), "string".into()),
        ],
    )
    .unwrap()
}

const SAFE: &str = r#"
permit (principal, action == Box::Action::"http:request", resource);
@id("wiki_scope")
forbid (principal, action == wiki::Action::"http_body", resource)
when   { context.input.method == "POST" && context.input.path == "/rest/search" }
unless { context.input.body_json && context.input has spaces &&
         ["eng", "docs"].containsAll(context.input.spaces) };
"#;

fn source(text: &str) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("http-body"),
        text: text.into(),
    }]
}

fn engine(text: &str, routes: Vec<HttpBodyRoute>) -> (tempfile::TempDir, PolicyEngine) {
    let dir = tempfile::tempdir().unwrap();
    let engine = PolicyEngine::open_staged_with_body_routes(
        &Operator::unanchored(),
        source(text),
        routes,
        &dir.path().join("h.redb"),
    )
    .expect("opens with the route fragment");
    (dir, engine)
}

fn refine(e: &PolicyEngine, path: &str, body: &[u8], encoded: bool) -> Decision {
    e.refine_http_body(
        &GovernedBox::assigned("t"),
        &Principal::agent(),
        "wiki",
        "wiki.example.com",
        443,
        "POST",
        path,
        body.len(),
        true,
        body,
        encoded,
    )
}

#[test]
fn allowed_spaces_pass_and_a_foreign_space_is_refused() {
    let (_d, e) = engine(SAFE, vec![wiki()]);
    assert!(
        refine(
            &e,
            "/rest/search",
            br#"{"filter":{"spaces":["eng"]}}"#,
            false
        )
        .is_allow()
    );
    assert!(
        !refine(
            &e,
            "/rest/search",
            br#"{"filter":{"spaces":["secret"]}}"#,
            false
        )
        .is_allow()
    );
    assert!(
        !refine(
            &e,
            "/rest/search",
            br#"{"filter":{"spaces":["eng","secret"]}}"#,
            false
        )
        .is_allow()
    );
}

#[test]
fn the_documented_form_refuses_an_unparseable_body() {
    let (_d, e) = engine(SAFE, vec![wiki()]);
    for body in [
        &br#"{"filter":{"spaces":["eng"],"spaces":["secret"]}}"#[..],
        // A first-key-wins upstream reads `secret`; a last-key-wins parser would see `eng`.
        br#"{"filter":{"spaces":["secret"],"spaces":["eng"]}}"#,
        b"spaces=eng",
        b"",
    ] {
        assert!(
            !refine(&e, "/rest/search", body, false).is_allow(),
            "{body:?}"
        );
    }
    assert!(
        !refine(
            &e,
            "/rest/search",
            br#"{"filter":{"spaces":["eng"]}}"#,
            true
        )
        .is_allow()
    );
}

#[test]
fn with_no_matching_rule_the_coarse_verdict_stands() {
    let (_d, e) = engine(SAFE, vec![wiki()]);
    assert!(refine(&e, "/upload", b"\x00binary", false).is_allow());
}

#[test]
fn an_unknown_route_fails_closed() {
    let (_d, e) = engine(SAFE, vec![wiki()]);
    let decision = e.refine_http_body(
        &GovernedBox::assigned("t"),
        &Principal::agent(),
        "other",
        "wiki.example.com",
        443,
        "POST",
        "/upload",
        0,
        true,
        b"",
        false,
    );
    assert!(!decision.is_allow());
}

#[test]
fn the_observer_sees_the_action_and_resource_but_no_body_value() {
    #[derive(Default)]
    struct Seen(std::sync::Mutex<Vec<String>>);
    impl policy::DecisionObserver for Seen {
        fn observed(&self, action: &str, resource: &str, decision: &Decision) {
            self.0
                .lock()
                .unwrap()
                .push(format!("{action} {resource} {decision:?}"));
        }
    }
    let seen = std::sync::Arc::new(Seen::default());
    let (_d, e) = engine(SAFE, vec![wiki()]);
    let e = e.observed_by(seen.clone());
    let _ = refine(
        &e,
        "/rest/search",
        br#"{"filter":{"spaces":["body-secret"]}}"#,
        false,
    );
    let lines = seen.0.lock().unwrap().join("\n");
    assert!(
        lines.contains(r#"wiki::Action::"http_body" wiki.example.com:443/rest/search"#),
        "{lines}"
    );
    assert!(!lines.contains("body-secret"), "{lines}");
}

#[test]
fn the_route_rule_is_ready_at_open_and_never_pending() {
    let (_d, e) = engine(SAFE, vec![wiki()]);
    assert!(
        e.finish_mcp_discovery().unwrap().is_empty(),
        "no degraded namespace"
    );
}

#[test]
fn a_rule_naming_an_undeclared_route_does_not_load_complete() {
    let error =
        PolicyEngine::validate_with_body_routes(&Operator::unanchored(), &source(SAFE), &[]);
    assert!(error.is_err());
    PolicyEngine::validate_with_body_routes(&Operator::unanchored(), &source(SAFE), &[wiki()])
        .expect("validates");
}

#[test]
fn a_route_colliding_with_an_mcp_server_namespace_is_refused_at_staging() {
    let (_d, e) = engine(
        "permit (principal, action, resource);",
        vec![HttpBodyRoute::new("issues", [("f".into(), "/a".into(), "long".into())]).unwrap()],
    );
    let fragment = policy::generate_mcp_schema(
        "issues",
        r#"{"result":{"tools":[{"name":"t",
        "description":"t","inputSchema":{"type":"object","properties":{}}}]}}"#,
    )
    .unwrap();
    let stage = e
        .stage_mcp_schema("issues", fragment)
        .expect("staging runs");
    assert!(
        matches!(&stage, SchemaStage::Rejected { reason } if reason.contains("issues")),
        "{stage:?}"
    );
}

#[test]
fn two_routes_with_one_namespace_are_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let r = |n: &str| HttpBodyRoute::new(n, [("f".into(), "/a".into(), "long".into())]).unwrap();
    assert!(
        PolicyEngine::open_staged_with_body_routes(
            &Operator::unanchored(),
            vec![],
            vec![r("a-b"), r("a_b")],
            &dir.path().join("h.redb"),
        )
        .is_err()
    );
}

#[test]
fn a_temporal_rule_counts_http_body_requests_by_a_declared_field() {
    // Refuse a `secret` search once two have been decided within the window.
    let text = r#"
    permit (principal, action == Box::Action::"http:request", resource);
    @id("secret_budget")
    forbid (principal, action == wiki::Action::"http_body", resource)
    when temporal {
        exists (total: Long). (
            (count for (t: Timepoint). where (
                formerly within 60s (
                    wiki::Action::"http_body"::request{ input.space: "secret" } && tp(t)
                )
            )) == total
            && total >= 3
        )
    };
    "#;
    let (_d, e) = engine(text, vec![wiki()]);
    let secret = br#"{"space":"secret"}"#;
    assert!(refine(&e, "/rest/search", br#"{"space":"eng"}"#, false).is_allow());
    assert!(refine(&e, "/rest/search", secret, false).is_allow());
    assert!(refine(&e, "/rest/search", secret, false).is_allow());
    assert!(!refine(&e, "/rest/search", secret, false).is_allow());
}

#[test]
fn a_mistyped_route_rule_is_refused_at_open_not_set_aside() {
    // The route's schema is known at open, so a route rule that does not validate can never
    // become valid by discovery. Setting it aside would silently drop a forbid.
    let dir = tempfile::tempdir().unwrap();
    let text = r#"
    permit (principal, action == Box::Action::"http:request", resource);
    forbid (principal, action == wiki::Action::"http_body", resource)
    when { context.input.spacez == "x" };
    "#;
    assert!(
        PolicyEngine::open_staged_with_body_routes(
            &Operator::unanchored(),
            source(text),
            vec![wiki()],
            &dir.path().join("h.redb"),
        )
        .is_err()
    );
}
