//! End-to-end tests driving the `writ` binary.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("writ-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox { dir }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.join(p)
    }

    fn run_with(&self, args: &[&str], stdin: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_writ"))
            .args(args)
            .current_dir(&self.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    /// Runs writ with empty stdin; returns (status, stdout, stderr).
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let out = self.run_with(args, b"");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Runs writ and expects success; returns stdout.
    fn ok(&self, args: &[&str]) -> String {
        let (code, out, err) = self.run(args);
        assert_eq!(code, 0, "writ {args:?} failed:\n{err}");
        out
    }

    /// Runs writ and expects `code`; returns stderr.
    fn fails(&self, args: &[&str], code: i32) -> String {
        let (got, out, err) = self.run(args);
        assert_eq!(
            got, code,
            "writ {args:?}: expected exit {code}\nstdout: {out}\nstderr: {err}"
        );
        err
    }

    fn append(&self, file: &str, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(file))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.path(file)).unwrap()
    }

    fn init(&self, name: &str) -> String {
        self.ok(&[
            "init",
            name,
            "--next-out",
            &format!("{name}-next.key"),
            "-q",
        ])
        .trim()
        .to_owned()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_and_key_files() {
    let s = Sandbox::new("init");
    let (code, out, err) = s.run(&["init", "me", "--next-out", "me-next.key"]);
    assert_eq!(code, 0, "{err}");
    let id = out.trim();
    assert!(id.starts_with("writ1") && id.len() == 63, "{id}");
    assert!(err.contains("created identity"));
    assert_eq!(s.ok(&["id", "me"]).trim(), id);
    for f in ["log.writ", "issued.writ", "next.writ", "current.key"] {
        assert!(s.path("me").join(f).exists(), "{f}");
    }
    #[cfg(unix)]
    {
        assert_eq!(mode(&s.path("me/current.key")), 0o600);
        assert_eq!(mode(&s.path("me-next.key")), 0o600);
    }
    // A comment says what the key is; then the seed.
    let key = s.read("me/current.key");
    let mut lines = key.lines();
    let comment = lines.next().unwrap();
    assert!(
        comment.starts_with("# writ current key for writ1") && comment.ends_with("(event 0)"),
        "{key}"
    );
    assert!(
        lines.next().unwrap().starts_with("WRIT-SECRET-KEY-1"),
        "{key}"
    );
    assert!(
        s.read("me-next.key")
            .starts_with("# writ next key for writ1")
    );

    // Never overwrite a key; never reuse a directory.
    let err = s.fails(&["init", "other", "--next-out", "me-next.key"], 2);
    assert!(err.contains("never overwrites"), "{err}");
    assert!(!s.path("other").exists());
    s.fails(&["init", "me", "--next-out", "x.key"], 2);
    // --next-out is required.
    let err = s.fails(&["init", "third"], 2);
    assert!(err.contains("--next-out"), "{err}");

    // Secrets to stdout: the id goes to stderr instead.
    let (code, out, err) = s.run(&["init", "piped", "--next-out", "-"]);
    assert_eq!(code, 0);
    assert!(
        out.starts_with("# writ next key for writ1")
            && out
                .lines()
                .nth(1)
                .is_some_and(|l| l.starts_with("WRIT-SECRET-KEY-1"))
            && out.lines().count() == 2,
        "{out}"
    );
    assert!(err.contains("created identity writ1"));
}

#[test]
fn names_grants_revocation() {
    let s = Sandbox::new("grants");
    s.init("me");
    let alice = s.init("alice");
    s.append("b.writ", &s.ok(&["name", "-i", "me", "alice", &alice]));
    s.append(
        "b.writ",
        &s.ok(&["grant", "-i", "me", "me alice", "(ssh nas)"]),
    );
    let out = s.ok(&[
        "check",
        "--as",
        "me",
        &alice,
        "(ssh nas disk)",
        "--in",
        "b.writ",
    ]);
    assert!(out.starts_with("allowed:"), "{out}");
    assert!(out.contains("me's alice is"), "{out}");
    // Too broad a question.
    let err = s.fails(
        &["check", "--as", "me", &alice, "(ssh)", "--in", "b.writ"],
        1,
    );
    assert!(err.contains("grants only (ssh nas)"), "{err}");
    // Quiet mode: status only.
    let (code, out, err) = s.run(&[
        "check", "-q", "--as", "me", "alice", "(ssh)", "--in", "b.writ",
    ]);
    assert_eq!((code, out.as_str(), err.as_str()), (1, "", ""));

    // Revoke by hash prefix.
    let grant = s.read("me/issued.writ");
    let issued_items = s.ok(&["show", "me/issued.writ"]);
    let hash = issued_items
        .lines()
        .find_map(|l| l.strip_prefix("grant "))
        .unwrap()
        .to_owned();
    assert!(!grant.is_empty());
    s.append("b.writ", &s.ok(&["revoke", "-i", "me", &hash[..10]]));
    let err = s.fails(
        &[
            "check",
            "--as",
            "me",
            "alice",
            "(ssh nas)",
            "--in",
            "b.writ",
        ],
        1,
    );
    assert!(err.contains("revoked by"), "{err}");
    // --as DIR brings the identity's own issuance log, revocation included.
    s.fails(&["check", "--as", "me", "alice", "(ssh nas)"], 1);
    // Ambiguous or unknown targets are refused.
    s.fails(&["revoke", "-i", "me", "zz"], 2);
}

#[test]
fn delegation_through_names() {
    let s = Sandbox::new("names");
    s.init("me");
    let alice = s.init("alice");
    let bob = s.init("bob");
    s.append("b.writ", &s.ok(&["name", "-i", "me", "alice", "alice"]));
    s.append("b.writ", &s.ok(&["name", "-i", "alice", "laptop", "bob"]));
    s.append(
        "b.writ",
        &s.ok(&[
            "grant",
            "-i",
            "me",
            "me alice laptop",
            "(zuko)",
            "--delegate",
        ]),
    );
    s.append("b.writ", &s.ok(&["export", "-i", "alice"]));
    s.ok(&["check", "--as", "me", &bob, "(zuko home)", "--in", "b.writ"]);
    let out = s.ok(&["resolve", "--as", "me", "alice laptop", "--in", "b.writ"]);
    assert_eq!(out.trim(), bob);
    let out = s.ok(&[
        "resolve",
        "--as",
        "me",
        &format!("{alice} laptop"),
        "--in",
        "b.writ",
    ]);
    assert_eq!(out.trim(), bob);
    s.fails(&["resolve", "--as", "me", "nobody", "--in", "b.writ"], 1);
    // A name path is not a concrete subject.
    let err = s.fails(
        &[
            "check", "--as", "me", "me alice", "(zuko)", "--in", "b.writ",
        ],
        2,
    );
    assert!(err.contains("writ resolve"), "{err}");

    // The proof alone convinces, and is smaller than everything.
    let proof = s.ok(&["prove", "--as", "me", "bob", "(zuko x)", "--in", "b.writ"]);
    std::fs::write(s.path("proof.writ"), &proof).unwrap();
    let id_me = s.ok(&["id", "me"]);
    s.ok(&[
        "check",
        "--as",
        id_me.trim(),
        &bob,
        "(zuko x)",
        "--in",
        "proof.writ",
    ]);
    let shown = s.ok(&["show", "proof.writ"]);
    assert_eq!(
        shown.matches("\ninception").count() + usize::from(shown.starts_with("inception")),
        2
    );
}

#[test]
fn leaf_sign_verify() {
    let s = Sandbox::new("leaf");
    s.init("me");
    s.append(
        "b.writ",
        &s.ok(&[
            "leaf",
            "-i",
            "me",
            "(release)",
            "--out",
            "leaf.key",
            "--expires",
            "2h",
        ]),
    );
    #[cfg(unix)]
    assert_eq!(mode(&s.path("leaf.key")), 0o600);
    std::fs::write(s.path("data"), b"hello").unwrap();
    let sig = s.ok(&["sign", "--leaf", "leaf.key", "-c", "app/v1", "data"]);
    std::fs::write(s.path("data.sig"), &sig).unwrap();
    let out = s.ok(&[
        "verify",
        "--as",
        "me",
        "-t",
        "(release)",
        "-c",
        "app/v1",
        "data",
        "data.sig",
        "--in",
        "b.writ",
    ]);
    assert!(out.starts_with("good signature by leaf:"), "{out}");
    let err = s.fails(
        &[
            "verify",
            "--as",
            "me",
            "-t",
            "(release)",
            "-c",
            "app/v2",
            "data",
            "data.sig",
            "--in",
            "b.writ",
        ],
        1,
    );
    assert!(err.contains("different context"), "{err}");
    std::fs::write(s.path("other"), b"hellO").unwrap();
    let err = s.fails(
        &[
            "verify",
            "--as",
            "me",
            "-t",
            "(release)",
            "-c",
            "app/v1",
            "other",
            "data.sig",
            "--in",
            "b.writ",
        ],
        1,
    );
    assert!(err.contains("does not match the data"), "{err}");
    // After the grant expires.
    let later = s.ok(&["show", "b.writ"]);
    assert!(later.contains("expires"));
    let err = s.fails(
        &[
            "verify",
            "--as",
            "me",
            "-t",
            "(release)",
            "-c",
            "app/v1",
            "data",
            "data.sig",
            "--in",
            "b.writ",
            "--at",
            "2099-01-01",
        ],
        1,
    );
    assert!(err.contains("expired"), "{err}");
    // Leaf limits.
    let err = s.fails(
        &[
            "leaf",
            "-i",
            "me",
            "()",
            "--out",
            "l2.key",
            "--expires",
            "25h",
        ],
        2,
    );
    assert!(err.contains("24 hours"), "{err}");
    let err = s.fails(&["leaf", "-i", "me", "()", "--out", "leaf.key"], 2);
    assert!(err.contains("never overwrites"), "{err}");
    // Renewal: grant to the leaf's public key again.
    let pubkey = s.ok(&["pubkey", "--leaf", "leaf.key"]);
    std::fs::write(s.path("leaf.pub"), pubkey).unwrap();
    let err = s.fails(&["grant", "-i", "me", "leaf.pub", "(release)"], 2);
    assert!(err.contains("--expires"), "{err}");
    s.ok(&[
        "grant",
        "-i",
        "me",
        "leaf.pub",
        "(release)",
        "--expires",
        "24h",
    ]);
    // Secret keys are not subjects.
    let err = s.fails(
        &[
            "grant",
            "-i",
            "me",
            "leaf.key",
            "(release)",
            "--expires",
            "1h",
        ],
        2,
    );
    assert!(err.contains("secret key"), "{err}");

    // Identity signatures, from stdin.
    let out = s.run_with(&["sign", "-i", "me", "-c", "app/v1"], b"hello");
    assert!(out.status.success());
    std::fs::write(s.path("me.sig"), &out.stdout).unwrap();
    s.ok(&[
        "verify", "--as", "me", "-t", "()", "-c", "app/v1", "data", "me.sig",
    ]);
}

#[test]
fn rotation_keeps_and_drops() {
    let s = Sandbox::new("rotate");
    s.init("me");
    let alice = s.init("alice");
    s.ok(&["grant", "-i", "me", &alice, "(kept)"]);
    s.ok(&["grant", "-i", "me", &alice, "(short)", "--expires", "1s"]);
    s.ok(&["leaf", "-i", "me", "(svc)", "--out", "leaf.key"]);
    // Names for a leaf key expire within a day, like grants to one.
    std::fs::write(s.path("leaf.pub"), s.ok(&["pubkey", "--leaf", "leaf.key"])).unwrap();
    let err = s.fails(&["name", "-i", "me", "svc", "leaf.pub"], 2);
    assert!(err.contains("must expire within 24 hours"), "{err}");
    s.fails(
        &["name", "-i", "me", "svc", "leaf.pub", "--expires", "2d"],
        2,
    );
    s.ok(&["name", "-i", "me", "svc", "leaf.pub", "--expires", "1h"]);
    std::fs::write(s.path("d"), b"x").unwrap();
    std::fs::write(s.path("d.sig"), s.ok(&["sign", "-i", "me", "-c", "c", "d"])).unwrap();
    // A data signature slipped into issued.writ whose signature doesn't
    // match its body: the rotation must not endorse it.
    let mut forged = libwrit::Item::decode_bundle(s.read("d.sig").as_bytes())
        .unwrap()
        .remove(0);
    let libwrit::Item::Signature(f) = &mut forged else {
        panic!("not a signature");
    };
    f.body.data = libwrit::Hash::of_data(b"evil");
    let forged = writ_sexp::armor::encode(&forged.encode());
    std::fs::write(s.path("evil"), b"evil").unwrap();
    std::fs::write(s.path("evil.sig"), &forged).unwrap();
    s.append("me/issued.writ", &forged);
    std::fs::write(s.path("old.key"), s.read("me/current.key")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2100));

    // The current key can't rotate.
    let err = s.fails(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "me/current.key",
            "--next-out",
            "n2.key",
        ],
        2,
    );
    assert!(err.contains("holds a current key"), "{err}");
    let (code, _, err) = s.run(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "me-next.key",
        "--next-out",
        "n2.key",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("kept 2 statements"), "{err}");
    assert!(
        err.contains("1 expired")
            && err.contains("2 statements for leaf keys")
            && err.contains("1 that were no longer valid"),
        "{err}"
    );
    s.ok(&["verify", "--as", "me", "-t", "()", "-c", "c", "d", "d.sig"]);
    s.fails(
        &[
            "verify", "--as", "me", "-t", "()", "-c", "c", "evil", "evil.sig",
        ],
        1,
    );
    let installed = s.read("me/current.key");
    assert_ne!(installed, s.read("old.key"));
    assert_ne!(installed, s.read("me-next.key"));
    // The old key is retired and refused.
    let err = s.fails(&["grant", "-i", "me", "--key", "old.key", &alice, "(x)"], 2);
    assert!(err.contains("no longer a current key"), "{err}");
    s.ok(&["grant", "-i", "me", &alice, "(fresh)"]);
    // Rotating again needs the new next key.
    s.fails(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "me-next.key",
            "--next-out",
            "n3.key",
        ],
        2,
    );

    for (tag, code) in [("(kept)", 0), ("(fresh)", 0), ("(short)", 1)] {
        s.fails(&["check", "--as", "me", &alice, tag], code);
    }
    // The kept signature still verifies.
    s.ok(&["verify", "--as", "me", "-t", "()", "-c", "c", "d", "d.sig"]);
}

#[test]
fn age_style_composition() {
    let s = Sandbox::new("stdio");
    // Next key on stdout; current key elsewhere.
    let out = s.run_with(
        &["init", "me", "--next-out", "-", "--key-out", "cur.key"],
        b"",
    );
    assert!(out.status.success());
    let next_key = out.stdout.clone();
    assert!(!s.path("me/current.key").exists());
    // Keys from stdin and from /dev/stdin.
    let cur = std::fs::read(s.path("cur.key")).unwrap();
    let alice = s.init("alice");
    let out = s.run_with(&["grant", "-i", "me", "--key", "-", &alice, "(a)"], &cur);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = s.run_with(
        &["grant", "-i", "me", "--key", "/dev/stdin", &alice, "(b)"],
        &cur,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Without a key: a clear error.
    let err = s.fails(&["grant", "-i", "me", &alice, "(c)"], 2);
    assert!(err.contains("--key"), "{err}");
    // Rotate with the next key on stdin, new next key on stdout.
    let out = s.run_with(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "-",
            "--next-out",
            "-",
            "--key-out",
            "cur2.key",
        ],
        &next_key,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.starts_with("# writ next key for") && text.contains("\nWRIT-SECRET-KEY-1"),
        "{text}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cur2.key"), "{err}");
    // Next keys only rotate; the new current key signs.
    let out = s.run_with(
        &["grant", "-i", "me", "--key", "-", &alice, "(d)"],
        &next_key,
    );
    assert_eq!(out.status.code(), Some(2));
    s.ok(&["grant", "-i", "me", "--key", "cur2.key", &alice, "(d)"]);
}

#[test]
fn k_of_n_and_friends() {
    let s = Sandbox::new("kofn");
    s.ok(&["keygen", "--out", "friend.key"]);
    std::fs::write(s.path("friend.pub"), s.ok(&["pubkey", "friend.key"])).unwrap();
    let (code, _, err) = s.run(&[
        "init",
        "me",
        "--next-out",
        "cold.keys",
        "--next-n",
        "2",
        "--next-k",
        "2",
        "--next-pub",
        "friend.pub",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("any 2 of these 3"), "{err}");
    let cold = s.read("cold.keys");
    let mut lines = cold.lines().filter(|l| !l.starts_with('#'));
    std::fs::write(s.path("cold1.key"), lines.next().unwrap()).unwrap();
    // One key is not enough.
    let err = s.fails(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "cold1.key",
            "--next-out",
            "n.key",
        ],
        2,
    );
    assert!(err.contains("needs 2 of the 3"), "{err}");
    // One of mine plus the friend's.
    let (code, _, err) = s.run(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "cold1.key",
        "--next-key",
        "friend.key",
        "--next-out",
        "n.key",
    ]);
    assert_eq!(code, 0, "{err}");
    // A threshold of half or less is refused; the default is a majority.
    let err = s.fails(
        &[
            "init",
            "weak",
            "--next-out",
            "w.keys",
            "--next-n",
            "2",
            "--next-k",
            "1",
        ],
        2,
    );
    assert!(err.contains("more than half"), "{err}");
    s.ok(&["init", "strong", "--next-out", "s.keys", "--next-n", "2"]);
    let shown = s.ok(&["show", "strong/next.writ"]);
    assert!(shown.contains("2 of 2"), "{shown}");
}

#[test]
fn state_ratchet_and_equivocation() {
    let s = Sandbox::new("state");
    s.init("me");
    let alice = s.init("alice");
    std::fs::write(
        s.path("trust.writ"),
        s.ok(&["grant", "-i", "me", &alice, "()", "--delegate"]),
    )
    .unwrap();
    let bob = s.init("bob");
    // A thief copies alice, warm key included; then alice rotates.
    copy_dir(&s.path("alice"), &s.path("alice-twin"));
    s.ok(&[
        "rotate",
        "-i",
        "alice",
        "--next-key",
        "alice-next.key",
        "--next-out",
        "a2.key",
        "-q",
    ]);
    std::fs::write(s.path("fresh.writ"), s.ok(&["export", "-i", "alice"])).unwrap();
    // The thief signs with the old key, and withholds the rotation.
    s.ok(&["grant", "-i", "alice-twin", &bob, "(y)"]);
    std::fs::write(s.path("stale.writ"), s.ok(&["export", "-i", "alice-twin"])).unwrap();

    // Without state, a stale bundle is believed.
    s.ok(&[
        "check",
        "--as",
        "me",
        &bob,
        "(y)",
        "--in",
        "trust.writ",
        "--in",
        "stale.writ",
    ]);
    // A verifier that has seen the rotation remembers it.
    s.ok(&[
        "check",
        "--as",
        "me",
        &alice,
        "()",
        "--in",
        "trust.writ",
        "--in",
        "fresh.writ",
        "--state",
        "st",
    ]);
    assert!(s.path("st/floor").exists());
    let err = s.fails(
        &[
            "check",
            "--as",
            "me",
            &bob,
            "(y)",
            "--in",
            "trust.writ",
            "--in",
            "stale.writ",
            "--state",
            "st",
        ],
        1,
    );
    assert!(err.contains("did not keep it"), "{err}");

    // The twin rotates differently with the same next key: equivocation.
    s.ok(&[
        "rotate",
        "-i",
        "alice-twin",
        "--next-key",
        "alice-next.key",
        "--next-out",
        "t2.key",
        "-q",
    ]);
    std::fs::write(s.path("twin.writ"), s.ok(&["export", "-i", "alice-twin"])).unwrap();
    let err = s.fails(
        &[
            "check",
            "--as",
            "me",
            &bob,
            "(y)",
            "--in",
            "trust.writ",
            "--in",
            "twin.writ",
            "--state",
            "st",
        ],
        1,
    );
    assert!(err.contains("two different versions"), "{err}");
    // Once seen, it stays seen.
    let err = s.fails(
        &[
            "check",
            "--as",
            "me",
            &alice,
            "()",
            "--in",
            "trust.writ",
            "--state",
            "st",
        ],
        1,
    );
    assert!(err.contains("two different versions"), "{err}");
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

#[test]
fn ssh_keys_and_max_validity() {
    let s = Sandbox::new("ssh");
    let (code, _, err) = s.run(&["init", "me", "--next-out", "n.key", "--max-validity", "30d"]);
    assert_eq!(code, 0, "{err}");
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&[7u8; 32]);
    let line = format!("ssh-ed25519 {} laptop", base64(&blob));
    let (code, _, err) = s.run(&["grant", "-i", "me", &line, "(ssh nas)"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("requires an expiry"), "{err}");
    let err = s.fails(
        &["grant", "-i", "me", &line, "(ssh nas)", "--expires", "60d"],
        2,
    );
    assert!(err.contains("within 30d"), "{err}");
    let err = s.fails(
        &[
            "grant",
            "-i",
            "me",
            &line,
            "(ssh)",
            "--delegate",
            "--expires",
            "1d",
        ],
        2,
    );
    assert!(
        err.contains("does not work with an application key"),
        "{err}"
    );
    std::fs::write(s.path("id_ed25519.pub"), format!("{line}\n")).unwrap();
    let out = s.ok(&["check", "--as", "me", "id_ed25519.pub", "(ssh nas)"]);
    assert!(out.contains("ssh-ed25519"), "{out}");
    s.fails(&["check", "--as", "me", &line, "(ssh other)"], 1);

    // A key type the format can't hold is refused up front, and printed
    // escaped; the identity stays usable.
    let kind = "ssh-\x1b[31mX";
    let mut blob = Vec::new();
    blob.extend_from_slice(&(kind.len() as u32).to_be_bytes());
    blob.extend_from_slice(kind.as_bytes());
    let line = format!("{kind} {}", base64(&blob));
    let err = s.fails(&["grant", "-i", "me", &line, "(e)", "--expires", "1d"], 2);
    assert!(err.contains("not a usable key type"), "{err}");
    assert!(!err.contains('\x1b'), "{err:?}");
    s.ok(&["id", "me"]);
    s.ok(&["export", "-i", "me"]);
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            s.push(if i <= c.len() {
                A[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    s
}

#[test]
fn usage_and_help() {
    let s = Sandbox::new("usage");
    let (code, out, _) = s.run(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("Questions"));
    let (code, out, _) = s.run(&["grant", "--help"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("--delegate") && out.contains("Usage:") && out.contains("writ grant -i DIR")
    );
    let err = s.fails(&["gran"], 2);
    assert!(err.contains("did you mean 'grant'"), "{err}");
    let err = s.fails(&["grant", "-i", "me"], 2);
    assert!(err.contains("missing SUBJECT TAG"), "{err}");
    let err = s.fails(&["check", "x", "()"], 2);
    assert!(err.contains("--as"), "{err}");
    let err = s.fails(&["grant", "--bogus"], 2);
    assert!(err.contains("unknown option --bogus"), "{err}");
    let (code, out, _) = s.run(&["--version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("writ "));
    let err = s.fails(&["show", "nonexistent"], 2);
    assert!(err.contains("nonexistent"), "{err}");
    std::fs::write(
        s.path("junk"),
        "-----BEGIN WRIT-----\nnope\n-----END WRIT-----\n",
    )
    .unwrap();
    let err = s.fails(&["show", "junk"], 2);
    assert!(err.contains("junk"), "{err}");
}

#[test]
fn rotation_survives_a_crash_before_the_log_write() {
    let s = Sandbox::new("crash");
    s.init("me");
    let log_before = std::fs::read(s.path("me/log.writ")).unwrap();
    let key_before = std::fs::read(s.path("me/current.key")).unwrap();
    s.ok(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "me-next.key",
        "--next-out",
        "n1.key",
        "-q",
    ]);
    // As if writ died after recording the new next authority and key, but
    // before appending the rotation to the log: the old current key is still
    // in place, and the new one is staged beside it.
    std::fs::write(s.path("me/log.writ"), log_before).unwrap();
    std::fs::remove_file(s.path("me/current.key")).unwrap();
    std::fs::write(s.path("me/current.key"), &key_before).unwrap();
    s.ok(&["keygen", "--out", "me/current.key.new"]);
    let (code, _, err) = s.run(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "me-next.key",
        "--next-out",
        "n2.key",
    ]);
    assert_eq!(code, 0, "{err}");
    let shown = s.ok(&["show", "me/next.writ"]);
    assert_eq!(shown.matches("authority").count(), 3, "{shown}");
}

#[cfg(unix)]
#[test]
fn secrets_are_never_steered() {
    let s = Sandbox::new("steer");
    // A FIFO or symlink planted where a key will go is refused.
    assert!(
        Command::new("mkfifo")
            .arg(s.path("trap"))
            .status()
            .unwrap()
            .success()
    );
    std::os::unix::fs::symlink(s.path("elsewhere"), s.path("link")).unwrap();
    for target in ["trap", "link"] {
        let err = s.fails(&["keygen", "--out", target], 2);
        assert!(err.contains("never overwrites"), "{err}");
    }
    assert!(!s.path("elsewhere").exists());
    s.fails(&["init", "me", "--next-out", "trap"], 2);
    assert!(!s.path("me").exists());
}

#[test]
fn a_key_with_a_future_role_is_not_retired() {
    let s = Sandbox::new("retire");
    s.init("me");
    std::fs::write(s.path("warm.pub"), s.ok(&["pubkey", "me/current.key"])).unwrap();
    let before = s.read("me/current.key");
    // The warm key joins the new next authority: it must survive.
    let (code, _, err) = s.run(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "me-next.key",
        "--next-out",
        "n.key",
        "--next-pub",
        "warm.pub",
        "--next-n",
        "1",
        "--next-k",
        "2",
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("still in use"), "{err}");
    let (code, _, err) = s.run(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "me-next.key",
        "--next-out",
        "n.key",
        "--next-pub",
        "warm.pub",
        "--next-n",
        "1",
        "--next-k",
        "2",
        "--key-out",
        "new.key",
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(s.read("me/current.key"), before);
}

#[test]
fn state_remembers_only_what_was_involved() {
    let s = Sandbox::new("scope");
    s.init("me");
    let alice = s.init("alice");
    let stranger = s.init("stranger");
    std::fs::write(
        s.path("b.writ"),
        s.ok(&["grant", "-i", "me", &alice, "(x)"]),
    )
    .unwrap();
    s.append("b.writ", &s.ok(&["export", "-i", "stranger"]));
    s.ok(&[
        "check", "--as", "me", &alice, "(x)", "--in", "b.writ", "--state", "st",
    ]);
    let logs: Vec<String> = std::fs::read_dir(s.path("st/logs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(!logs.iter().any(|l| l.starts_with(&stranger)), "{logs:?}");
    assert!(
        logs.iter().any(|l| l.starts_with(&alice)) || logs.len() == 1,
        "{logs:?}"
    );
    // Asking about someone, and being told no, doesn't remember them either:
    // a server checking ids its clients send would otherwise store one log
    // per request.
    s.fails(
        &[
            "check", "--as", "me", &stranger, "(x)", "--in", "b.writ", "--state", "st",
        ],
        1,
    );
    let logs: Vec<String> = std::fs::read_dir(s.path("st/logs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(!logs.iter().any(|l| l.starts_with(&stranger)), "{logs:?}");
}

#[test]
fn state_remembers_revocations() {
    let s = Sandbox::new("revstate");
    let me = s.init("me");
    let alice = s.init("alice");
    let grant = s.read("me/log.writ") + &s.ok(&["grant", "-i", "me", &alice, "(x)"]);
    std::fs::write(s.path("old.writ"), &grant).unwrap();
    let check = |bundle: &str| {
        s.run(&[
            "check", "--as", &me, &alice, "(x)", "--in", bundle, "--state", "st",
        ])
        .0
    };
    assert_eq!(check("old.writ"), 0);
    let hash = s
        .ok(&["show", "me/issued.writ"])
        .lines()
        .find_map(|l| l.strip_prefix("grant "))
        .unwrap()
        .to_owned();
    std::fs::write(
        s.path("new.writ"),
        grant + &s.ok(&["revoke", "-i", "me", &hash[..10]]),
    )
    .unwrap();
    assert_eq!(check("new.writ"), 1);
    // A bundle without the revocation doesn't bring the grant back.
    assert_eq!(check("old.writ"), 1);
}

#[test]
fn as_id_is_never_a_directory() {
    let s = Sandbox::new("asid");
    let me = s.init("me");
    let alice = s.init("alice");
    s.init("evil");
    std::fs::write(
        s.path("b.writ"),
        s.ok(&["grant", "-i", "evil", &alice, "(admin)"]),
    )
    .unwrap();
    // A directory named after my id, holding someone else's identity.
    std::fs::rename(s.path("evil"), s.path(&me)).unwrap();
    s.fails(
        &["check", "--as", &me, &alice, "(admin)", "--in", "b.writ"],
        1,
    );
}

#[test]
fn color_follows_the_conventions() {
    let s = Sandbox::new("color");
    let esc = |args: &[&str], env: &[(&str, &str)]| {
        let out = Command::new(env!("CARGO_BIN_EXE_writ"))
            .args(args)
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR_FORCE")
            .envs(env.iter().copied())
            .current_dir(&s.dir)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).contains('\x1b')
    };
    // Not a terminal: no color unless asked.
    assert!(!esc(&["--help"], &[]));
    assert!(esc(&["--color=always", "--help"], &[]));
    assert!(esc(&["--help", "--color", "always"], &[]));
    assert!(esc(&["--help"], &[("CLICOLOR_FORCE", "1")]));
    assert!(!esc(&["--help"], &[("CLICOLOR_FORCE", "0")]));
    assert!(!esc(
        &["--help"],
        &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")]
    ));
    assert!(esc(&["--color=always", "--help"], &[("NO_COLOR", "1")]));
    assert!(!esc(
        &["--color=never", "--help"],
        &[("CLICOLOR_FORCE", "1")]
    ));
    let err = s.fails(&["--color=sometimes", "--help"], 2);
    assert!(err.contains("auto, always, or never"), "{err}");
}

#[test]
fn help_comes_in_two_lengths() {
    let s = Sandbox::new("helplen");
    let short = s.ok(&["grant", "-h"]);
    let long = s.ok(&["grant", "--help"]);
    assert!(short.contains("Usage:") && !short.contains("Examples:"));
    assert!(long.contains("Examples:") && long.contains("Arguments:"));
    assert_eq!(s.ok(&["help", "grant"]), long);
    for cmd in [
        "init",
        "id",
        "rotate",
        "export",
        "name",
        "grant",
        "revoke",
        "leaf",
        "sign",
        "verify",
        "check",
        "resolve",
        "prove",
        "show",
        "keygen",
        "pubkey",
        "completions",
    ] {
        s.ok(&[cmd, "--help"]);
    }
}

#[test]
fn an_interrupted_key_install_is_finished() {
    let s = Sandbox::new("install");
    s.init("me");
    s.ok(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "me-next.key",
        "--same-next",
        "-q",
    ]);
    let current = s.read("me/current.key");
    // As if writ died after committing the rotation but before moving the
    // new key into place.
    std::fs::rename(s.path("me/current.key"), s.path("me/current.key.new")).unwrap();
    s.ok(&["init", "alice", "--next-out", "a.key", "-q"]);
    let (code, _, err) = s.run(&["grant", "-i", "me", "alice", "(x)"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("interrupted rotation"), "{err}");
    assert_eq!(s.read("me/current.key"), current);
    assert!(!s.path("me/current.key.new").exists());
}

#[test]
fn same_next_keeps_the_recovery_keys() {
    let s = Sandbox::new("samenext");
    s.init("me");
    let alice = s.init("alice");
    for i in 0..2 {
        let (code, _, err) = s.run(&[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "me-next.key",
            "--same-next",
        ]);
        assert_eq!(code, 0, "rotation {i}: {err}");
        assert!(err.contains("next keys    unchanged"), "{err}");
    }
    s.ok(&["grant", "-i", "me", &alice, "(x)"]);
    s.ok(&["check", "--as", "me", &alice, "(x)"]);
    let err = s.fails(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "me-next.key",
            "--same-next",
            "--next-out",
            "x.key",
        ],
        2,
    );
    assert!(err.contains("nothing to write"), "{err}");
}

#[test]
fn parallel_issuers_lose_no_records() {
    let s = Sandbox::new("parallel");
    s.init("me");
    let alice = s.init("alice");
    let n = 20;
    std::thread::scope(|scope| {
        for i in 0..n {
            let (s, alice) = (&s, &alice);
            scope.spawn(move || {
                s.ok(&["grant", "-i", "me", alice, &format!("(t{i})"), "-q"]);
            });
        }
    });
    let shown = s.ok(&["show", "me/issued.writ"]);
    for i in 0..n {
        assert!(
            shown.contains(&format!("(t{i})")),
            "(t{i}) missing:\n{shown}"
        );
    }
    assert_eq!(s.read("me/issued.writ").matches("-----BEGIN").count(), n);
}

#[cfg(unix)]
#[test]
fn outputs_never_overwrite_and_failures_record_nothing() {
    let s = Sandbox::new("outputs");
    s.init("me");
    let issued = s.read("me/issued.writ");
    std::fs::write(s.path("data"), b"hello").unwrap();
    s.ok(&["keygen", "--out", "precious.key"]);
    let precious = s.read("precious.key");
    std::os::unix::fs::symlink(s.path("elsewhere"), s.path("dangling")).unwrap();

    // An existing file or a symlink, even a dangling one, is refused, before
    // anything is signed, written or recorded.
    for target in ["precious.key", "dangling"] {
        let err = s.fails(
            &[
                "leaf",
                "-i",
                "me",
                "(x)",
                "--out",
                "l.key",
                "--grant-out",
                target,
            ],
            2,
        );
        assert!(err.contains("never overwrites"), "{err}");
        assert!(!s.path("l.key").exists());
        let err = s.fails(
            &["sign", "-i", "me", "-c", "app/v1", "data", "--out", target],
            2,
        );
        assert!(err.contains("never overwrites"), "{err}");
    }
    assert_eq!(s.read("precious.key"), precious);
    assert!(!s.path("elsewhere").exists());
    assert_eq!(s.read("me/issued.writ"), issued);

    // A failure after the output was opened removes it again.
    let err = s.fails(
        &[
            "sign", "-i", "me", "-c", "app/v1", "missing", "--out", "x.sig",
        ],
        2,
    );
    assert!(err.contains("missing"), "{err}");
    assert!(!s.path("x.sig").exists());
    let err = s.fails(
        &[
            "leaf",
            "-i",
            "me",
            "(x)",
            "--out",
            "precious.key",
            "--grant-out",
            "g.writ",
        ],
        2,
    );
    assert!(err.contains("never overwrites"), "{err}");
    assert!(!s.path("g.writ").exists());
    assert_eq!(s.read("me/issued.writ"), issued);

    // Both outputs can't share a destination.
    let err = s.fails(
        &[
            "leaf",
            "-i",
            "me",
            "(x)",
            "--out",
            "-",
            "--grant-out",
            "/dev/stdout",
        ],
        2,
    );
    assert!(err.contains("must differ"), "{err}");

    s.ok(&[
        "sign", "-i", "me", "-c", "app/v1", "data", "--out", "data.sig",
    ]);
    s.ok(&[
        "leaf",
        "-i",
        "me",
        "(x)",
        "--out",
        "l.key",
        "--grant-out",
        "g.writ",
    ]);
    s.ok(&[
        "verify", "--as", "me", "-t", "()", "-c", "app/v1", "data", "data.sig",
    ]);
    assert!(s.ok(&["show", "g.writ"]).starts_with("grant "));
}

#[cfg(unix)]
#[test]
fn descriptor_outputs_append() {
    let s = Sandbox::new("descriptors");
    std::fs::write(s.path("keys.txt"), "# kept\n").unwrap();
    // `writ keygen --out /dev/stdout >> keys.txt`
    let file = std::fs::OpenOptions::new()
        .append(true)
        .open(s.path("keys.txt"))
        .unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_writ"))
        .args(["keygen", "--out", "/dev/stdout"])
        .current_dir(&s.dir)
        .stdout(file)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    // `writ keygen --out /dev/fd/3 3>> keys.txt`, and to a pipe.
    let sh = |script: &str| {
        Command::new("sh")
            .args(["-c", script, env!("CARGO_BIN_EXE_writ")])
            .current_dir(&s.dir)
            .stderr(Stdio::null())
            .output()
            .unwrap()
    };
    assert!(
        sh(r#""$0" keygen --out /dev/fd/3 3>> keys.txt"#)
            .status
            .success()
    );
    let piped = sh(r#""$0" keygen --out /dev/fd/3 3>&1 > /dev/null"#);
    assert!(piped.status.success());
    assert!(String::from_utf8_lossy(&piped.stdout).contains("WRIT-SECRET-KEY-1"));
    let keys = s.read("keys.txt");
    assert!(keys.starts_with("# kept\n"), "{keys}");
    assert_eq!(keys.matches("WRIT-SECRET-KEY-1").count(), 2, "{keys}");

    // Two secrets never share standard output, however it is named.
    for (key_out, next_out) in [("/dev/stdout", "-"), ("-", "/dev/fd/1")] {
        let err = s.fails(
            &["init", "me", "--key-out", key_out, "--next-out", next_out],
            2,
        );
        assert!(err.contains("must differ"), "{err}");
        assert!(!s.path("me").exists());
    }
    s.init("me");
    let err = s.fails(
        &[
            "rotate",
            "-i",
            "me",
            "--next-key",
            "me-next.key",
            "--next-out",
            "-",
            "--key-out",
            "/dev/stdout",
        ],
        2,
    );
    assert!(err.contains("must differ"), "{err}");
}

#[test]
fn keys_never_go_where_writ_keeps_state() {
    let s = Sandbox::new("keypaths");
    for f in [
        "issued.writ",
        "log.writ",
        "next.writ",
        "current.key",
        ".lock",
    ] {
        let next_out = format!("me/{f}");
        let err = s.fails(
            &["init", "me", "--next-out", &next_out, "--key-out", "k.key"],
            2,
        );
        assert!(err.contains("inside me"), "{f}: {err}");
        assert!(!s.path("me").exists(), "{f}");
    }
    let err = s.fails(
        &[
            "init",
            "me",
            "--next-out",
            "n.key",
            "--key-out",
            "me/log.writ",
        ],
        2,
    );
    assert!(err.contains("inside me"), "{err}");
    assert!(!s.path("n.key").exists() && !s.path("k.key").exists());
    // An empty directory that was already there is left in place.
    std::fs::create_dir(s.path("empty")).unwrap();
    s.fails(&["init", "empty", "--next-out", "empty/next.writ"], 2);
    assert!(s.path("empty").is_dir());
    s.ok(&["init", "empty", "--next-out", "empty-next.key", "-q"]);

    let id = s.ok(&[
        "init",
        "me",
        "--next-out",
        "me-next.key",
        "--key-out",
        "me/current.key",
    ]);
    assert_eq!(s.ok(&["id", "me"]), id);
    for out in ["me/current.key.new", "me/x.key", "./me/../me/new.key"] {
        let err = s.fails(
            &[
                "rotate",
                "-i",
                "me",
                "--next-key",
                "me-next.key",
                "--next-out",
                out,
            ],
            2,
        );
        assert!(err.contains("inside me"), "{out}: {err}");
        let err = s.fails(
            &[
                "rotate",
                "-i",
                "me",
                "--next-key",
                "me-next.key",
                "--next-out",
                "n.key",
                "--key-out",
                out,
            ],
            2,
        );
        assert!(err.contains("inside me"), "{out}: {err}");
    }
    assert!(!s.path("n.key").exists());
    s.ok(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        "me-next.key",
        "--next-out",
        "n.key",
    ]);
}

#[test]
fn concurrent_inits_of_one_directory() {
    let s = Sandbox::new("initrace");
    let n = 6;
    let results: Vec<(i32, String)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let s = &s;
                scope.spawn(move || {
                    let next = format!("next{i}.key");
                    let (code, out, _) = s.run(&["init", "me", "--next-out", &next, "-q"]);
                    (code, out)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let winners: Vec<usize> = (0..n).filter(|i| results[*i].0 == 0).collect();
    assert_eq!(winners.len(), 1, "{results:?}");
    let w = winners[0];
    assert_eq!(s.ok(&["id", "me"]), results[w].1);
    let alice = s.init("alice");
    s.ok(&["grant", "-i", "me", &alice, "(x)"]);
    s.ok(&[
        "rotate",
        "-i",
        "me",
        "--next-key",
        &format!("next{w}.key"),
        "--next-out",
        "n.key",
    ]);
}

#[cfg(unix)]
#[test]
fn endless_inputs_are_cut_off() {
    let s = Sandbox::new("endless");
    s.init("me");
    let err = s.fails(&["show", "/dev/zero"], 2);
    assert!(err.contains("the limit is 256 MiB"), "{err}");
    let err = s.fails(
        &["check", "--as", "me", "me", "(x)", "--in", "/dev/zero"],
        2,
    );
    assert!(err.contains("the limit is 256 MiB"), "{err}");
    let err = s.fails(&["pubkey", "/dev/zero"], 2);
    assert!(err.contains("the limit is 64 KiB"), "{err}");
    let err = s.fails(&["grant", "-i", "me", "--key", "/dev/zero", "me", "(x)"], 2);
    assert!(err.contains("the limit is 64 KiB"), "{err}");
}

#[test]
fn options_are_parsed_strictly() {
    let s = Sandbox::new("strictargs");
    s.init("me");
    let alice = s.init("alice");
    let me_issued = s.read("me/issued.writ");
    let alice_issued = s.read("alice/issued.writ");
    // A single-value option given twice is a usage error, not the last one.
    let err = s.fails(&["grant", "-i", "me", "-i", "alice", &alice, "(x)"], 2);
    assert!(err.contains("--identity can be given only once"), "{err}");
    let err = s.fails(&["grant", "-ime", "--identity=alice", &alice, "(x)"], 2);
    assert!(err.contains("only once"), "{err}");
    assert_eq!(s.read("me/issued.writ"), me_issued);
    assert_eq!(s.read("alice/issued.writ"), alice_issued);
    // --color as the value of another option is that value.
    s.ok(&["grant", "-i", "me", &alice, "(x)", "--note", "--color"]);
    s.ok(&[
        "grant", "-i", "me", &alice, "(y)", "--note", "--color", "--color", "never",
    ]);
    let shown = s.ok(&["show", "me/issued.writ"]);
    assert_eq!(shown.matches("--color").count(), 2, "{shown}");
    s.ok(&["--color=never", "id", "me", "--color", "always"]);
}

/// Every command in the README's tour works as written, with `cat` standing
/// in for age.
#[cfg(unix)]
#[test]
fn readme_tour_runs() {
    let s = Sandbox::new("readme");
    std::fs::write(s.path("app.tar"), b"app").unwrap();
    std::fs::write(s.path("status.json"), b"{}").unwrap();
    let bin = Path::new(env!("CARGO_BIN_EXE_writ")).parent().unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let readme = include_str!("../../../README.md");
    let mut in_block = false;
    let mut ran = 0;
    for line in readme.lines() {
        match line {
            "```sh" => in_block = true,
            "```" => in_block = false,
            _ if !in_block || line.is_empty() || line.starts_with('#') => {}
            _ => {
                let command = line.replace("age -p", "cat").replace("age -d", "cat");
                let out = Command::new("bash")
                    .args(["-c", &command])
                    .env("PATH", &path)
                    .current_dir(&s.dir)
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                let expected = if line.contains("# denied") { 1 } else { 0 };
                assert_eq!(
                    out.status.code(),
                    Some(expected),
                    "{line}\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                ran += 1;
            }
        }
    }
    assert!(ran > 15, "{ran}");
}

#[test]
fn grants_with_several_tags() {
    let s = Sandbox::new("multitag");
    s.init("me");
    let alice = s.init("alice");
    let out = s.ok(&[
        "grant",
        "-i",
        "me",
        &alice,
        "(files docs)",
        "(files photos)",
    ]);
    std::fs::write(s.path("b.writ"), &out).unwrap();
    let check = |tag: &str| s.run(&["check", "--as", "me", &alice, tag, "--in", "b.writ"]);
    assert_eq!(check("(files docs)").0, 0);
    let (code, out, _) = check("(files photos 2026)");
    assert_eq!(code, 0);
    // The explanation shows the tag of the grant this chain used.
    assert!(
        out.contains("(files photos)") && !out.contains("(files docs)"),
        "{out}"
    );
    assert_eq!(check("(files)").0, 1);
    // A tag another covers is refused, naming both.
    let err = s.fails(&["grant", "-i", "me", &alice, "(ssh)", "(ssh nas)"], 2);
    assert!(err.contains("(ssh) already covers (ssh nas)"), "{err}");
    // Leaf keys take several tags too.
    s.ok(&[
        "leaf", "-i", "me", "(svc a)", "(svc b)", "--out", "leaf.key",
    ]);
    // No tag at all is a usage error.
    let err = s.fails(&["grant", "-i", "me", &alice], 2);
    assert!(err.contains("missing TAG"), "{err}");
}

/// A small HTTP server for `--fetch`: serves files from `dir` by path, and
/// `/evil` as a redirect to a file: URL. Runs until the test process ends.
fn serve(dir: PathBuf) -> String {
    use std::io::{BufRead, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            // Skip the headers.
            let mut header = String::new();
            while reader.read_line(&mut header).is_ok_and(|n| n > 2) {
                header.clear();
            }
            let path = line.split(' ').nth(1).unwrap_or("/").to_owned();
            let mut out = &stream;
            let response = if path == "/evil" {
                b"HTTP/1.1 302 Found\r\nLocation: file:///etc/passwd\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            } else {
                match std::fs::read(dir.join(path.trim_start_matches('/'))) {
                    Ok(body) => [
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes(),
                        body,
                    ]
                    .concat(),
                    Err(_) => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                }
            };
            let _ = out.write_all(&response);
        }
    });
    base
}

#[test]
fn revocation_records_publish_and_fetch() {
    let s = Sandbox::new("records");
    let base = serve(s.dir.clone());
    s.init("me");
    let alice = s.init("alice");
    // pub publishes its records at base/pub/record.writ, its own record file.
    let url = format!("{base}/pub/record.writ");
    let (code, _, err) = s.run(&[
        "init",
        "pub",
        "--next-out",
        "pub-next.key",
        "--publish",
        &url,
        "--max-age",
        "2h",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("publish") && err.contains(&url), "{err}");
    assert!(s.read("pub/record.writ").contains("BEGIN WRIT"));
    // me (local, as a directory) delegates to pub; pub grants alice.
    let pub_id = s.ok(&["id", "pub"]).trim().to_owned();
    s.append(
        "b.writ",
        &s.ok(&["grant", "-i", "me", &pub_id, "()", "--delegate"]),
    );
    s.append("b.writ", &s.ok(&["grant", "-i", "pub", &alice, "(x)"]));
    s.append("b.writ", &s.read("pub/log.writ"));
    let check = |extra: &[&str]| {
        let mut args = vec!["check", "--as", "me", &alice, "(x)", "--in", "b.writ"];
        args.extend_from_slice(extra);
        s.run(&args)
    };
    // No record in the input: refused, saying where to get one.
    let (code, _, err) = check(&[]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("no older than 2h") && err.contains(&url) && err.contains("--fetch"),
        "{err}"
    );
    // The record, given directly or fetched: allowed.
    assert_eq!(check(&["--in", "pub/record.writ"]).0, 0);
    let (code, _, err) = check(&["--fetch"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("fetched"), "{err}");
    // Near the end of the record's life, the answer warns.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let soon = format!("@{}", now + 100 * 60);
    let (code, _, err) = check(&["--in", "pub/record.writ", "--at", &soon]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("stop counting in"), "{err}");
    // pub revokes its grant; the new record says so, and a fetch finds it.
    let hash = s
        .ok(&["show", "pub/issued.writ"])
        .lines()
        .find_map(|l| l.strip_prefix("grant "))
        .unwrap()
        .to_owned();
    s.ok(&["revoke", "-i", "pub", &hash[..10]]);
    let (code, _, err) = check(&["--fetch"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("revoked"), "{err}");
    // export --record signs a new one and prints log and record.
    let out = s.ok(&["export", "-i", "pub", "--record"]);
    assert_eq!(out.matches("BEGIN WRIT").count(), 2, "{out}");
    // A rotation keeps publishing and signs a record under the new event.
    s.ok(&[
        "rotate",
        "-i",
        "pub",
        "--next-key",
        "pub-next.key",
        "--same-next",
    ]);
    assert_eq!(s.read("pub/record.writ").matches("BEGIN WRIT").count(), 3);
}

#[test]
fn fetch_refuses_other_schemes_and_publish_is_checked() {
    let s = Sandbox::new("fetchguard");
    let base = serve(s.dir.clone());
    s.init("me");
    let alice = s.init("alice");
    let url = format!("{base}/evil");
    s.ok(&[
        "init",
        "bad",
        "--next-out",
        "bad-next.key",
        "--publish",
        &url,
    ]);
    let bad = s.ok(&["id", "bad"]).trim().to_owned();
    s.append(
        "b.writ",
        &s.ok(&["grant", "-i", "me", &bad, "()", "--delegate"]),
    );
    s.append("b.writ", &s.ok(&["grant", "-i", "bad", &alice, "(y)"]));
    s.append("b.writ", &s.read("bad/log.writ"));
    let (code, _, err) = s.run(&[
        "check", "--as", "me", &alice, "(y)", "--in", "b.writ", "--fetch",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("only http and https"), "{err}");
    // The settings are checked when they are made.
    let err = s.fails(
        &["init", "x1", "--next-out", "x1.key", "--max-age", "30m"],
        2,
    );
    assert!(err.contains("at least 1h"), "{err}");
    let err = s.fails(
        &[
            "init",
            "x2",
            "--next-out",
            "x2.key",
            "--publish",
            "ftp://h/r",
        ],
        2,
    );
    assert!(err.contains("http:// or https://"), "{err}");
    let (code, _, err) = s.run(&[
        "init",
        "x3",
        "--next-out",
        "x3.key",
        "--publish",
        "https://h.example/a",
        "--publish",
        "https://H.example:8443/b",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("every --publish URL is on h.example"), "{err}");
}

#[test]
fn require_records_refuses_non_publishers_unless_local() {
    let s = Sandbox::new("requirerec");
    let me = s.init("me");
    let alice = s.init("alice");
    std::fs::write(
        s.path("b.writ"),
        s.read("me/log.writ") + &s.ok(&["grant", "-i", "me", &alice, "(z)"]),
    )
    .unwrap();
    // me as a directory is local: its own grants need no record.
    assert_eq!(
        s.run(&[
            "check",
            "--as",
            "me",
            &alice,
            "(z)",
            "--in",
            "b.writ",
            "--require-records"
        ])
        .0,
        0
    );
    // me by id is not, and publishes no records.
    let (code, _, err) = s.run(&[
        "check",
        "--as",
        &me,
        &alice,
        "(z)",
        "--in",
        "b.writ",
        "--require-records",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("publishes no records"), "{err}");
}

#[test]
fn writ_contexts_are_reserved() {
    let s = Sandbox::new("reserved");
    s.init("me");
    std::fs::write(s.path("f"), b"data").unwrap();
    let err = s.fails(
        &["sign", "-i", "me", "--context", "writ/v1/channel/x", "f"],
        2,
    );
    assert!(err.contains("reserved for writ"), "{err}");
}
