//! M6: agent config is copied into a pocket with credentials stripped, and comes back only
//! through `pocket config pull`, which shows a diff and needs confirmation.

use pocket_tests::cli::Env;
use pocket_tests::kvm_or_skip;

#[test]
fn config_copied_in_stripped_and_pulled_back_only_with_confirmation() {
    let Some(a) = kvm_or_skip() else { return };
    let env = Env::new("agentcfg", a.system.parent().unwrap());
    let home = env.root.join("home");
    let key = "sk-ant-api03-HOSTREALKEY0123456789abcdefghijklmnopqrstuvwx";
    let w = |rel: &str, s: &str| {
        let p = home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    };
    w(
        ".claude/settings.json",
        &format!(
            r#"{{"model":"opus","env":{{"ANTHROPIC_API_KEY":"{key}","MCP_TOKEN":"mcp-secret-value"}}}}"#
        ),
    );
    w(".claude/CLAUDE.md", "Be brief.\n");
    w(".claude/commands/review.md", "Review the diff.\n");
    w(
        ".claude/.credentials.json",
        r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-NEVERCOPY"}}"#,
    );
    w(".claude/projects/x/session.jsonl", "transcript\n");
    w(
        ".claude.json",
        r#"{"hasCompletedOnboarding":true,"theme":"dark","oauthAccount":{"emailAddress":"me@example.com"},"projects":{"/home/me/secret-project":{}}}"#,
    );
    w(
        ".codex/config.toml",
        "model = \"o3\"\nbearer_token = \"codex-bearer-secret\"\n",
    );
    w(
        ".codex/auth.json",
        r#"{"OPENAI_API_KEY":"sk-proj-NEVERCOPY"}"#,
    );
    assert!(env.pocket_stdin(&["login", "claude"], key).status.success());

    let n = format!("cfg-{}", std::process::id());
    env.ok(&["new", &n, "--preset", "test", "--no-repo", "--detach"]);
    let sh = |s: &str| env.ok(&["exec", &n, "--", "sh", "-c", s]);
    let ph = sh("echo $ANTHROPIC_API_KEY").trim().to_string();
    let listing = sh("cd $HOME && find .claude .claude.json .codex -type f | sort");
    eprintln!("guest files:\n{listing}");
    assert_eq!(
        listing.lines().collect::<Vec<_>>(),
        [
            ".claude.json",
            ".claude/CLAUDE.md",
            ".claude/commands/review.md",
            ".claude/settings.json",
            ".codex/config.toml"
        ]
    );
    let all = sh("cd $HOME && cat .claude.json .claude/settings.json .codex/config.toml");
    eprintln!("{all}");
    for never in [
        key,
        "mcp-secret-value",
        "codex-bearer-secret",
        "NEVERCOPY",
        "me@example.com",
        "secret-project",
    ] {
        assert!(!all.contains(never), "{never} copied into the pocket");
    }
    assert!(
        all.contains(&ph),
        "the API key became the pocket's placeholder"
    );
    assert!(all.contains("<redacted by pocket>"));
    assert!(all.contains("\"hasCompletedOnboarding\": true"));
    assert!(
        all.contains(&ph[ph.len() - 20..]),
        "placeholder key pre-approved"
    );

    // The agent edits its config, including a hook that would run on the host.
    sh(
        r#"cd $HOME && sed -i 's/"opus"/"sonnet"/' .claude/settings.json && sed -i 's/^{/{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"touch \/tmp\/pwned"}]}]},/' .claude/settings.json && echo 'Fix the bug.' > .claude/commands/fix.md"#,
    );
    let before = std::fs::read_to_string(home.join(".claude/settings.json")).unwrap();

    // No terminal and no --yes: shown, not applied.
    let o = env.pocket(&["config", "pull", &n]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        out.contains("~/.claude/settings.json (modified)") && out.contains("⚠ touches: hooks"),
        "{out}"
    );
    assert!(
        out.contains("+ ")
            && out.contains("touch /tmp/pwned")
            && out.contains("~/.claude/commands/fix.md (new)")
    );
    assert!(!out.contains(key), "the diff shows no real secret");
    assert_eq!(
        std::fs::read_to_string(home.join(".claude/settings.json")).unwrap(),
        before
    );
    assert!(!home.join(".claude/commands/fix.md").exists());
    let preview = env.json(&["config", "pull", &n]);
    assert_eq!(preview.as_array().unwrap().len(), 2, "{preview}");

    // Confirmed: written, with the real key restored where the placeholder was.
    env.ok(&["config", "pull", &n, "--yes"]);
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert_eq!(after["model"], "sonnet");
    assert_eq!(after["env"]["ANTHROPIC_API_KEY"], key);
    assert_eq!(after["env"]["MCP_TOKEN"], "mcp-secret-value");
    assert!(after["hooks"]["Stop"].is_array());
    assert_eq!(
        std::fs::read_to_string(home.join(".claude/commands/fix.md")).unwrap(),
        "Fix the bug.\n"
    );
    assert!(
        !std::path::Path::new("/tmp/pwned").exists()
            || std::fs::metadata("/tmp/pwned").is_ok_and(|m| m
                .modified()
                .unwrap()
                .elapsed()
                .unwrap()
                .as_secs()
                > 600)
    );
    let again = env.ok(&["config", "pull", &n]);
    assert!(again.contains("matches the host"), "{again}");
}
