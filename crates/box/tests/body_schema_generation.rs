//! `policy generate-schema` composes each `[egress.<name>] body.fields` route's `http_body` action.

use std::path::PathBuf;
use std::process::Command;

fn box_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_strands-box"))
}

#[test]
fn generate_schema_writes_a_body_routes_http_body_action() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("workspace");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    std::fs::create_dir_all(&config).expect("create the config directory");
    std::fs::write(
        config.join("box.toml"),
        r#"name = "schema"
box_dir = "/nonexistent/schema-generation"

[egress.wiki]
destinations = ["wiki.example.com"]
secret.ref = "env://WIKI_TOKEN"

[egress.wiki.body.fields]
spaces = { pointer = "/filter/spaces", type = "set<string>" }
"#,
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actions =
        std::fs::read_to_string(directory.join("actions.cedarschema")).expect("actions written");
    for needle in [
        "namespace wiki",
        "action \"http_body\"",
        "spaces?: Set<String>",
    ] {
        assert!(actions.contains(needle), "missing {needle}: {actions}");
    }
}
