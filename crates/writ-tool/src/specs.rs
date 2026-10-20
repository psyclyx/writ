//! Every command's interface and documentation, in one place. `--help`, the
//! man pages and the shell completions are generated from this file.
//!
//! Style: simple technical English. Short sentences, present tense, the
//! active voice, and no jargon where a plain word will do.

use crate::args::{Arg, Opt, Spec, Value, arg, flag, opt};

const WHEN: &[&str] = &["auto", "always", "never"];
const SHELLS: &[&str] = &["bash", "zsh", "fish"];

/// Options accepted before the command.
pub static GLOBAL_OPTS: &[Opt] = &[opt(
    "color",
    "WHEN",
    Value::Choice(WHEN),
    "when to use color: auto, always, or never (default: auto)",
)];

/// What `writ` is, for `writ --help` and writ(1).
pub const OVERVIEW: &[&str] = &[
    "writ makes and checks signed statements about keys: who is who (names) \
     and who may do what (grants).",
    "Each person or machine has an identity: a short log of keys with an id \
     that never changes. An identity signs statements with its current key. \
     A separate next key, kept offline, can replace the keys later without \
     changing the id. This is called rotation.",
    "Statements are small signed items. They are stored and sent as text \
     files called bundles. A bundle is any number of items, in any order, so \
     `cat a.writ b.writ > c.writ` makes a bundle too.",
    "To check a statement, you name the identities you trust (usually your \
     own) with --as. writ then looks for a chain of grants from them to the \
     subject. Each grant in a chain can only narrow what the one before it \
     allowed.",
];

/// Shared by the commands that answer questions.
const MATERIAL: &str = "writ reads statements, identity logs and revocations from the --in \
     files, from standard input when it is a file or a pipe, and from each --as \
     identity directory. The order does not matter.";

const TIME: &str = "writ uses the current time, but never a time before its own build date. \
     With --state, it also never uses a time before the newest statement it has \
     seen from the --as identities, so setting the clock back does not make \
     expired grants valid again. Use --at to ask about another time.";

const SUBJECTS: &str = "    writ1...                   an id
    DIR                        an identity directory (its id is used)
    'writ1... bob laptop'      a name path: whoever bob calls laptop
    FILE                       a public key file, or an OpenSSH .pub file
    'ssh-ed25519 AAAA...'      an OpenSSH public key";

const IDENTITY: Opt = opt(
    "identity",
    "DIR",
    Value::Identity,
    "the identity that signs the statement",
)
.short('i')
.required();
const KEY: Opt = opt(
    "key",
    "PATH",
    Value::File,
    "secret key file (default: DIR/current.key); give one --key per key \
     when several keys must sign; '-' means standard input",
)
.many();
const EXPIRES: Opt = opt(
    "expires",
    "WHEN",
    Value::Text,
    "when the statement expires: a duration such as 30d or 12h, or a date \
     such as 2027-01-01 (default: never)",
);
const NOTE: Opt = opt(
    "note",
    "TEXT",
    Value::Text,
    "text to show with the statement; writ does not use it",
);
const QUIET_ISSUE: Opt = flag("quiet", "print only the statement").short('q');
const NEXT_N: Opt = opt(
    "next-n",
    "N",
    Value::Text,
    "how many new next keys to make (default: 1)",
);
const NEXT_K: Opt = opt(
    "next-k",
    "K",
    Value::Text,
    "how many next keys must sign a rotation (default: more than half of them)",
);
const NEXT_PUB: Opt = opt(
    "next-pub",
    "PATH",
    Value::File,
    "add another person's public key (from `writ pubkey`) to the next keys",
)
.many();

const AS: Opt = opt(
    "as",
    "ID",
    Value::Id,
    "the identity whose point of view to use: an id or an identity directory",
)
.required()
.many();
const IN: Opt = opt(
    "in",
    "PATH",
    Value::File,
    "read statements from PATH; '-' means standard input",
)
.many();
const AT: Opt = opt(
    "at",
    "TIME",
    Value::Text,
    "answer for TIME instead of now: 2027-01-01, 2027-01-01T12:00Z, or \
     @SECONDS",
);
const STATE: Opt = opt(
    "state",
    "DIR",
    Value::NewDir,
    "keep state in DIR between runs: the identity logs, revocations and \
     revocation records seen, and the clock floor",
);
const LEAF_CEILING: Opt = opt(
    "leaf-ceiling",
    "DUR",
    Value::Text,
    "accept grants to leaf keys only if they last at most DUR (at most 24h)",
);
const QUIET_QUERY: Opt = flag("quiet", "print nothing; only set the exit status").short('q');
const FETCH: Opt = flag(
    "fetch",
    "when an answer needs a revocation record that is missing or too old, get \
     it from the URLs its identity publishes, and ask again",
);
const REQUIRE_RECORDS: Opt = flag(
    "require-records",
    "refuse statements by identities that publish no revocation records, \
     except roots given as directories",
);
const PUBLISH: Opt = opt(
    "publish",
    "URL",
    Value::Text,
    "a URL where this identity's revocation record will be published; give \
     one --publish per URL, at most 4, on different hosts",
)
.many();
const MAX_AGE: Opt = opt(
    "max-age",
    "DUR",
    Value::Text,
    "how old a revocation record may be before verifiers refuse it; a new \
     record must be signed and published at least this often (default 7d, \
     at least 1h)",
);
/// Query commands: what --fetch and records mean.
const RECORDS: &str = "An identity may publish revocation records (see writ-init(1)). \
     Then its long-lived statements count only with a record from it that is \
     younger than its max-age; a record also lists what it revoked. Records \
     come from the input, from --state, or with --fetch from the URLs in the \
     identity's log. A record is signed, so it does not matter who delivers it.";

const SUBJECT_ARG: Arg = arg(
    "SUBJECT",
    Value::Subject,
    "an id, an identity directory, a key file, or an OpenSSH public key",
);
const TAG_ARG: Arg = arg(
    "TAG",
    Value::Text,
    "a list of words from general to specific, such as '(ssh nas)'",
);

const TAGS_ARG: Arg = arg(
    "TAG",
    Value::Text,
    "a list of words from general to specific, such as '(ssh nas)'; \
     several TAGs make one grant that covers each of them",
)
.many();

pub static INIT: Spec = Spec {
    name: "init",
    about: "create an identity",
    synopsis: None,
    args: &[arg(
        "DIR",
        Value::NewDir,
        "the directory to create; it must not exist, or must be empty",
    )],
    opts: &[
        opt(
            "next-out",
            "PATH",
            Value::OutFile,
            "where to write the next key, outside DIR; '-' means standard output",
        )
        .required(),
        NEXT_N,
        NEXT_K,
        NEXT_PUB,
        opt(
            "key-out",
            "PATH",
            Value::OutFile,
            "where to write the current key (default: DIR/current.key)",
        ),
        opt(
            "max-validity",
            "DUR",
            Value::Text,
            "require every statement to expire within DUR, such as 90d",
        ),
        PUBLISH,
        MAX_AGE,
        flag("quiet", "print only the id").short('q'),
    ],
    description: &[
        "Create a new identity in DIR and print its id.",
        "An identity has two kinds of keys. The current key signs statements. \
         writ writes it to DIR/current.key. The next key can only rotate the \
         identity: replace its keys and keep its id. Keep the next key \
         offline. You must say where it goes with --next-out.",
        "Key files are plain text. writ never overwrites a file, and creates \
         key files that only you can read. To encrypt keys, use age(1):",
        "    writ init me --next-out - | age -p > me-next.key.age",
        "The next keys can be K of N keys held by different people. For \
         example, 2 of 3: your own offline key, a friend's key, and a key in \
         a safe. K must be more than half of N, so that two separate groups of \
         holders can't each rotate.",
        "With --publish or --max-age, the identity publishes revocation \
         records: a signed list of what it has revoked, made again at least \
         every max-age. Verifiers then accept its long-lived statements only \
         with a record younger than that, so a revocation reaches them within \
         max-age. writ writes the file to publish to DIR/record.writ; put it \
         at each URL, and run `writ export -i DIR --record` at least once per \
         max-age (from cron, for example) to make a new one. If no new record \
         reaches a verifier for longer than max-age, it refuses those \
         statements. Only a rotation can change these settings.",
    ],
    examples: &[
        (
            "Create an identity, with the next key encrypted by age:",
            "writ init me --next-out - | age -p > me-next.key.age",
        ),
        (
            "Next keys held by three people, any two of whom can rotate:",
            "writ init org --next-out mine.key --next-pub alice.pub --next-pub bob.pub --next-k 2",
        ),
    ],
    see_also: &["rotate", "keygen", "pubkey"],
};

pub static ID: Spec = Spec {
    name: "id",
    about: "print the id of an identity",
    synopsis: None,
    args: &[arg("DIR", Value::Identity, "an identity directory")],
    opts: &[],
    description: &[
        "Print the id of the identity in DIR. An id looks like writ1... and \
         never changes, even when the identity rotates its keys.",
    ],
    examples: &[("Use your id in a script:", "me=$(writ id me)")],
    see_also: &["init"],
};

pub static ROTATE: Spec = Spec {
    name: "rotate",
    about: "replace the keys of an identity, keeping its id",
    synopsis: Some(
        "-i DIR --next-key PATH... (--next-out PATH | --same-next) [--key-out PATH] \
         [--key-pub PATH]... [--key-k K] [--next-n N] [--next-k K] [--next-pub PATH]... \
         [--max-validity DUR | --no-max-validity] [--publish URL]... [--max-age DUR | \
         --no-publish] [-q]",
    ),
    args: &[],
    opts: &[
        opt("identity", "DIR", Value::Identity, "the identity to rotate")
            .short('i')
            .required(),
        opt(
            "next-key",
            "PATH",
            Value::File,
            "a next key, from init or the last rotate; give one --next-key per \
             key when several must sign; '-' means standard input",
        )
        .required()
        .many(),
        opt(
            "next-out",
            "PATH",
            Value::OutFile,
            "where to write the new next key, outside DIR; '-' means standard output",
        ),
        flag(
            "same-next",
            "keep the next keys you have, instead of making new ones",
        ),
        opt(
            "key-out",
            "PATH",
            Value::OutFile,
            "where to write the new current key (default: in place of \
             DIR/current.key)",
        ),
        opt(
            "key-pub",
            "PATH",
            Value::File,
            "add another person's public key (from `writ pubkey`) to the current keys",
        )
        .many(),
        opt(
            "key-k",
            "K",
            Value::Text,
            "how many current keys must sign each statement (default: more than \
             half of them)",
        ),
        NEXT_N,
        NEXT_K,
        NEXT_PUB,
        opt(
            "max-validity",
            "DUR",
            Value::Text,
            "set a new limit on how long statements may last",
        ),
        flag(
            "no-max-validity",
            "remove the limit on how long statements may last",
        ),
        PUBLISH,
        MAX_AGE,
        flag("no-publish", "stop publishing revocation records"),
        flag("quiet", "print nothing on success").short('q'),
    ],
    description: &[
        "Rotate the identity in DIR: replace its current keys, and keep its id.",
        "The next keys (--next-key) sign the rotation, and nothing else. writ \
         makes a new current key and writes it to --key-out, or in place of \
         DIR/current.key. Then it makes new next keys and writes them to \
         --next-out, or, with --same-next, keeps the next keys you have. \
         Keeping them suits next keys held by friends or kept in a safe.",
        "After rotating, destroy the next keys you gave with --next-key, \
         unless you used --same-next: they can still sign a rotation that \
         conflicts with this one.",
        "A rotation lists the statements that stay valid. writ keeps every \
         statement and signature in DIR/issued.writ that is still valid: \
         correctly signed, not revoked, not expired, and not a name or grant \
         for a leaf key. Anything else signed with the old current key \
         becomes invalid for every verifier that sees the rotation. Use this \
         to recover from a stolen current key. If whoever stole it could also \
         write to DIR/issued.writ, read it first (writ show < \
         DIR/issued.writ) and revoke anything you did not sign.",
        "With --key-pub, the current keys include other people's keys, and \
         --key-k of them must sign each statement. Use this for an identity \
         that a group shares.",
    ],
    examples: &[
        (
            "Rotate, with the next keys encrypted by age:",
            "writ rotate -i me --next-key <(age -d me-next.key.age) --next-out - | age -p > me-next2.key.age",
        ),
        (
            "Recover from a stolen current key, keeping the next keys:",
            "writ rotate -i me --next-key <(age -d me-next.key.age) --same-next",
        ),
    ],
    see_also: &["init", "export"],
};

pub static EXPORT: Spec = Spec {
    name: "export",
    about: "print the log and valid statements of an identity",
    synopsis: None,
    args: &[],
    opts: &[
        opt("identity", "DIR", Value::Identity, "the identity to export")
            .short('i')
            .required(),
        flag(
            "all",
            "also print expired and revoked statements, and data signatures",
        ),
        flag(
            "record",
            "print the log and a new, signed revocation record instead: the file \
             to publish",
        ),
        KEY,
    ],
    description: &[
        "Print a bundle with the log of the identity in DIR and every \
         statement it issued that is valid now, including revocations. Give \
         this bundle to the people who check your statements.",
        "Data signatures are left out, because they travel with the data \
         they sign.",
        "With --record, writ signs a new revocation record with the current \
         key, writes the log and the record to DIR/record.writ, and prints \
         them. Run it at least once per max-age and publish the result at the \
         URLs given to `writ init --publish`.",
    ],
    examples: &[
        ("Publish your statements:", "writ export -i me > me.writ"),
        (
            "Make and publish a new revocation record, daily from cron:",
            "writ export -i me --record | ssh web 'cat > www/writ/me.writ'",
        ),
    ],
    see_also: &["show", "prove"],
};

pub static NAME: Spec = Spec {
    name: "name",
    about: "say who a name refers to",
    synopsis: None,
    args: &[
        arg(
            "NAME",
            Value::Text,
            "the name: one word, or a quoted string",
        ),
        arg("SUBJECT", Value::Subject, "who the name refers to"),
    ],
    opts: &[IDENTITY, KEY, EXPIRES, NOTE, QUIET_ISSUE],
    description: &[
        "Say that, for the identity in DIR, NAME refers to SUBJECT. Names are \
         local: 'me alice' is whoever you call alice, and someone else's \
         alice is a different name. A name can refer to more than one \
         subject. It then works as a group.",
        "SUBJECT can be:",
        SUBJECTS,
        "A name for a leaf key must expire within 24 hours, like a grant to \
         one. writ prints the signed statement and adds it to DIR/issued.writ.",
    ],
    examples: &[
        (
            "Call an identity alice:",
            "writ name -i me alice writ1qqq... >> bundle.writ",
        ),
        (
            "Add an SSH key to the group 'laptops':",
            "writ name -i me laptops ~/.ssh/id_ed25519.pub >> bundle.writ",
        ),
    ],
    see_also: &["grant", "resolve"],
};

pub static GRANT: Spec = Spec {
    name: "grant",
    about: "grant one or more tags to SUBJECT",
    synopsis: None,
    args: &[SUBJECT_ARG, TAGS_ARG],
    opts: &[
        IDENTITY,
        KEY,
        flag(
            "delegate",
            "let SUBJECT grant TAG, or part of it, to others",
        ),
        EXPIRES,
        NOTE,
        QUIET_ISSUE,
    ],
    description: &[
        "Grant each TAG to SUBJECT, signed by the identity in DIR.",
        "A tag is a list of words from general to specific, such as \
         (ssh nas). A grant of (ssh) also covers (ssh nas) and \
         (ssh nas backup). The tag () covers everything.",
        "Several TAGs make one statement that grants each of them, as that \
         many grants would. It is signed, revoked and kept as one, and costs \
         one signature. No TAG may cover another.",
        "With --delegate, SUBJECT can grant TAG, or a narrower tag, to \
         others. A chain of grants can only narrow: each holder gets at \
         most what the grant before it allowed.",
        "A grant to a name path goes to whoever the path names. For example, \
         a grant to 'me alice laptops' goes to whatever alice calls her \
         laptops, now and in the future.",
        "SUBJECT can be:",
        SUBJECTS,
        "A grant to a leaf key must expire within 24 hours. writ prints the \
         signed statement and adds it to DIR/issued.writ.",
    ],
    examples: &[
        (
            "Let alice log in to nas over SSH:",
            "writ grant -i me 'me alice' '(ssh nas)' >> bundle.writ",
        ),
        (
            "Let a build machine sign releases (its signatures verify for as long as \
             this grant does, so give it no expiry, and revoke it if the machine \
             is lost):",
            "writ grant -i me builder '(release)' >> bundle.writ",
        ),
    ],
    see_also: &["name", "revoke", "check"],
};

pub static REVOKE: Spec = Spec {
    name: "revoke",
    about: "revoke a statement or signature",
    synopsis: None,
    args: &[arg(
        "TARGET",
        Value::File,
        "the start of its hash (at least 6 hex digits), or a file with the item",
    )],
    opts: &[IDENTITY, KEY, NOTE, QUIET_ISSUE],
    description: &[
        "Revoke a statement or data signature that the identity in DIR \
         issued. The commands that issue statements print the start of the \
         hash; `writ show DIR/issued.writ` prints all of them.",
        "A revocation is final. To undo it, issue the statement again. \
         Verifiers learn about a revocation only when they see it, so add \
         it to the bundles you give them.",
    ],
    examples: &[(
        "Revoke a grant:",
        "writ revoke -i me 3fa2c1d0 >> bundle.writ",
    )],
    see_also: &["show", "export"],
};

pub static LEAF: Spec = Spec {
    name: "leaf",
    about: "make a short-lived leaf key and grant tags to it",
    synopsis: None,
    args: &[TAGS_ARG],
    opts: &[
        IDENTITY,
        KEY,
        opt(
            "out",
            "PATH",
            Value::OutFile,
            "where to write the secret leaf key; '-' means standard output",
        )
        .required(),
        opt(
            "grant-out",
            "PATH",
            Value::OutFile,
            "where to write the grant, a new file (default: standard output)",
        ),
        opt(
            "expires",
            "WHEN",
            Value::Text,
            "how long the key lives, at most 24h (default: 24h)",
        ),
        flag(
            "delegate",
            "let the leaf key grant TAG to others (who can't grant further)",
        ),
        NOTE,
        flag("quiet", "print only the grant").short('q'),
    ],
    description: &[
        "Make a leaf key and grant each TAG to it. Leaf keys use ML-DSA-65 and \
         Ed25519. They sign and verify quickly, and their signatures are \
         smaller than an identity's. A leaf key lives at most 24 hours.",
        "To keep using a leaf key, grant to its public key again (`writ \
         pubkey --leaf KEY` prints it), or make a new one.",
        "A leaf key can sign data. With --delegate it can also issue grants, \
         but those grants can't be delegated further.",
        "A signature by a leaf key verifies only while the leaf key's grant \
         is live, so use leaf keys for things that are signed again often, \
         not for releases.",
    ],
    examples: &[(
        "Make a key for a machine that signs a status file every hour:",
        "writ leaf -i me '(status)' --out ci.key >> bundle.writ",
    )],
    see_also: &["sign", "grant", "pubkey"],
};

pub static SIGN: Spec = Spec {
    name: "sign",
    about: "sign a file",
    synopsis: Some("(-i DIR [--key PATH]... | --leaf KEY) -c CONTEXT [--out PATH] [-q] [FILE]"),
    args: &[arg(
        "FILE",
        Value::File,
        "the file to sign (default: standard input)",
    )
    .optional()],
    opts: &[
        opt("identity", "DIR", Value::Identity, "sign as this identity").short('i'),
        KEY,
        opt(
            "leaf",
            "KEY",
            Value::File,
            "sign with this secret leaf key instead; the signature verifies \
             only while the leaf key's grant is live",
        ),
        opt(
            "context",
            "CONTEXT",
            Value::Text,
            "what the signature is for, such as example/release/v1",
        )
        .short('c')
        .required(),
        opt(
            "out",
            "PATH",
            Value::OutFile,
            "write the signature to PATH, a new file, instead of standard output",
        ),
        flag("quiet", "print only the signature").short('q'),
    ],
    description: &[
        "Sign FILE and print the signature. The context says what the \
         signature is for. A verifier must ask for the same context, so a \
         signature made for one purpose can't be used for another.",
        "Signatures by an identity are added to DIR/issued.writ, so that a \
         later rotation keeps them. A signature by a leaf key verifies only \
         while the leaf key's grant is live, at most 24 hours unless the \
         grant is renewed, so sign releases and other lasting things as an \
         identity.",
    ],
    examples: &[
        (
            "Sign a release:",
            "writ sign -i release -c example/release/v1 app.tar > app.tar.sig",
        ),
        (
            "Sign a status file with a leaf key:",
            "writ sign --leaf ci.key -c example/status/v1 status.json > status.json.sig",
        ),
    ],
    see_also: &["verify", "leaf"],
};

pub static VERIFY: Spec = Spec {
    name: "verify",
    about: "check a signature and what its signer may do",
    synopsis: None,
    args: &[
        arg(
            "FILE",
            Value::File,
            "the signed file; '-' means standard input",
        ),
        arg("SIGNATURE", Value::File, "the signature file"),
    ],
    opts: &[
        AS,
        opt(
            "tag",
            "TAG",
            Value::Text,
            "what the signer must hold, such as '(release)'",
        )
        .short('t')
        .required(),
        opt(
            "context",
            "CONTEXT",
            Value::Text,
            "what the signature must be for",
        )
        .short('c')
        .required(),
        IN,
        AT,
        STATE,
        LEAF_CEILING,
        FETCH,
        REQUIRE_RECORDS,
        QUIET_QUERY,
    ],
    description: &[
        "Check that SIGNATURE signs FILE for CONTEXT, and that the signer \
         holds TAG. If so, writ prints the chain of grants that shows it and \
         exits with status 0. If not, it prints the reasons to standard error \
         and exits with status 1.",
        MATERIAL,
        RECORDS,
        TIME,
    ],
    examples: &[(
        "Check a release:",
        "writ verify --as me -t '(release)' -c example/release/v1 app.tar app.tar.sig < bundle.writ",
    )],
    see_also: &["sign", "check"],
};

pub static CHECK: Spec = Spec {
    name: "check",
    about: "check that SUBJECT holds TAG",
    synopsis: None,
    args: &[
        SUBJECT_ARG,
        arg("TAG", Value::Text, "what to check for, such as '(ssh nas)'"),
    ],
    opts: &[
        AS,
        IN,
        AT,
        STATE,
        LEAF_CEILING,
        FETCH,
        REQUIRE_RECORDS,
        QUIET_QUERY,
    ],
    description: &[
        "Check whether SUBJECT holds TAG, from the point of view of the --as \
         identity. If it does, writ prints the chain of statements that shows \
         it and exits with status 0. If not, it prints the reasons to \
         standard error and exits with status 1.",
        "Holding a tag also means holding every narrower tag: whoever holds \
         (ssh) holds (ssh nas).",
        MATERIAL,
        RECORDS,
        TIME,
    ],
    examples: &[
        (
            "May alice log in to nas?",
            "writ check --as me alice '(ssh nas)' < bundle.writ",
        ),
        (
            "Use the answer in a script:",
            "if writ check -q --as me \"$key\" '(ssh nas)' < bundle.writ; then ...; fi",
        ),
    ],
    see_also: &["prove", "resolve", "grant"],
};

pub static RESOLVE: Spec = Spec {
    name: "resolve",
    about: "list the subjects a name refers to",
    synopsis: None,
    args: &[arg(
        "NAMEPATH",
        Value::Text,
        "names to follow, such as 'alice laptops'",
    )],
    opts: &[
        AS,
        IN,
        AT,
        STATE,
        LEAF_CEILING,
        flag("verbose", "also print the statements behind each answer").short('v'),
        FETCH,
        REQUIRE_RECORDS,
        QUIET_QUERY,
    ],
    description: &[
        "Print the subjects that NAMEPATH refers to, one per line, with ids \
         in full. A name path can start with an id or an identity directory. \
         If it doesn't, it starts at the first --as identity: 'alice \
         laptops' means the laptops of your alice.",
        MATERIAL,
        RECORDS,
        TIME,
    ],
    examples: &[(
        "List alice's laptops:",
        "writ resolve --as me 'alice laptops' < bundle.writ",
    )],
    see_also: &["name", "check"],
};

pub static PROVE: Spec = Spec {
    name: "prove",
    about: "print only the statements that show SUBJECT holds TAG",
    synopsis: None,
    args: &[SUBJECT_ARG, TAG_ARG],
    opts: &[
        AS,
        IN,
        AT,
        STATE,
        LEAF_CEILING,
        FETCH,
        REQUIRE_RECORDS,
        QUIET_QUERY,
    ],
    description: &[
        "Like `writ check`, but print a bundle with only the identity logs \
         and statements the answer needs. Give a verifier this proof instead \
         of everything you have. Statements show who you know, so share only \
         what a verifier needs.",
        MATERIAL,
        RECORDS,
    ],
    examples: &[(
        "Send only what nas needs to let alice in:",
        "writ prove --as me alice '(ssh nas)' < bundle.writ > alice-nas.writ",
    )],
    see_also: &["check", "export"],
};

pub static SHOW: Spec = Spec {
    name: "show",
    about: "print bundles in readable form",
    synopsis: None,
    args: &[arg(
        "FILE",
        Value::File,
        "bundle files (default: standard input)",
    )
    .optional()
    .many()],
    opts: &[],
    description: &[
        "Print each item in the bundles: identity events, statements, data \
         signatures, keys. Ids and hashes are printed in full.",
    ],
    examples: &[(
        "Find the hash of a statement to revoke:",
        "writ show me/issued.writ",
    )],
    see_also: &["export", "revoke"],
};

pub static KEYGEN: Spec = Spec {
    name: "keygen",
    about: "make a secret key",
    synopsis: None,
    args: &[],
    opts: &[opt(
        "out",
        "PATH",
        Value::OutFile,
        "where to write the key (default: standard output)",
    )],
    description: &[
        "Make a new secret key. Use it when someone asks you to hold one of \
         their next keys: give them the public key from `writ pubkey`, and \
         keep the secret key safe.",
    ],
    examples: &[(
        "Make a key for a friend's identity:",
        "writ keygen --out for-alice.key && writ pubkey for-alice.key > for-alice.pub",
    )],
    see_also: &["pubkey", "init"],
};

pub static PUBKEY: Spec = Spec {
    name: "pubkey",
    about: "print the public key of a secret key",
    synopsis: None,
    args: &[arg(
        "KEYFILE",
        Value::File,
        "a secret key file (default: standard input)",
    )
    .optional()],
    opts: &[flag("leaf", "the key is a leaf key")],
    description: &[
        "Print the public key of each secret key in KEYFILE, as a bundle \
         item. Identity public keys are for --next-pub. A leaf public key \
         can be the subject of a grant, for example to renew the leaf key.",
    ],
    examples: &[(
        "Renew a leaf key for another day:",
        "writ pubkey --leaf ci.key > ci.pub && writ grant -i me ci.pub '(status)' --expires 24h",
    )],
    see_also: &["keygen", "leaf"],
};

pub static COMPLETIONS: Spec = Spec {
    name: "completions",
    about: "print a shell completion script",
    synopsis: None,
    args: &[arg("SHELL", Value::Choice(SHELLS), "bash, zsh, or fish")],
    opts: &[],
    description: &[
        "Print a script that lets SHELL complete writ commands, options, and \
         file names.",
        "To load it, run the line for your shell, or add it to your shell's \
         startup file (~/.bashrc, ~/.zshrc, or ~/.config/fish/config.fish):",
        "    bash:  source <(writ completions bash)
    zsh:   source <(writ completions zsh)        (after compinit)
    fish:  writ completions fish | source",
        "eval \"$(writ completions SHELL)\" works too, but only with the double \
         quotes: without them, the shell joins the script into one line, and \
         it does nothing.",
        "To install the script as a file instead, which makes the shell start \
         faster:",
        "    bash:  writ completions bash > ~/.local/share/bash-completion/completions/writ
    zsh:   writ completions zsh > ~/.zfunc/_writ
           (with fpath=(~/.zfunc $fpath) before compinit in ~/.zshrc)
    fish:  writ completions fish > ~/.config/fish/completions/writ.fish",
        "Packages install these files for you.",
    ],
    examples: &[(
        "Load completions in ~/.zshrc:",
        "autoload -Uz compinit && compinit\nsource <(writ completions zsh)",
    )],
    see_also: &[],
};

/// The commands, grouped for `writ --help` and writ(1).
pub static GROUPS: &[(&str, &[&Spec])] = &[
    ("Identities", &[&INIT, &ID, &ROTATE, &EXPORT]),
    ("Statements", &[&NAME, &GRANT, &REVOKE, &LEAF]),
    ("Signatures", &[&SIGN, &VERIFY]),
    ("Questions", &[&CHECK, &RESOLVE, &PROVE, &SHOW]),
    ("Keys", &[&KEYGEN, &PUBKEY]),
    ("Shell", &[&COMPLETIONS]),
];

/// Every command, in display order.
pub fn all() -> impl Iterator<Item = &'static Spec> {
    GROUPS.iter().flat_map(|(_, specs)| specs.iter().copied())
}

/// The date on the man pages; bump with each release.
pub const MAN_DATE: &str = "2026-10-12";

/// Sections of writ(1) after DESCRIPTION.
pub static MANUAL: &[(&str, &[&str])] = &[
    (
        "IDENTITIES AND KEYS",
        &[
            "An identity is a log of key events. The first event creates the \
             identity, and its hash is the id. Later events, called rotations, \
             replace the keys. The id stays the same.",
            "Identity keys use SLH-DSA-SHAKE-128s, a signature scheme whose \
             security rests only on hash functions. Each event names the \
             current keys, which sign statements, and commits to the next \
             keys, which can sign only the next rotation. A rotation makes new current keys, \
             and can keep the same next keys, so next keys held by friends or \
             kept in a safe serve for many rotations. A thief who steals the \
             current key can't rotate the identity, and a rotation makes \
             everything the thief signed invalid for every verifier that sees \
             it.",
            "An identity can have several keys, of which K must sign, and K \
             must be more than half of them. This allows identities shared by \
             a group, and recovery with the help of friends.",
        ],
    ),
    (
        "STATEMENTS AND BUNDLES",
        &[
            "There are three kinds of statements. A name says who a name \
             refers to. A grant gives a tag to a subject. A revocation cancels \
             an earlier statement or data signature by the same identity. \
             Names and grants may expire. A statement is identified by the \
             hash of its contents; its signatures are not part of the hash.",
            "Items are stored as armored text: blocks between \
             -----BEGIN WRIT----- and -----END WRIT----- lines. A file of such \
             blocks is a bundle. `writ show` prints any bundle in readable \
             form.",
        ],
    ),
    (
        "TAGS",
        &[
            "A tag is a list of words, from general to specific: (ssh), \
             (ssh nas), (zuko home relay). A tag covers itself and every longer \
             tag that starts with it. The empty tag () covers everything. \
             There are no wildcards, and words are compared exactly: (ssh nas) \
             does not cover (ssh nasa).",
            "Along a chain of grants, the subject holds the longest of the \
             tags, if each tag starts with the one before it. If two tags in \
             the chain differ, the chain grants nothing.",
        ],
    ),
    (
        "NAMES",
        &[
            "Names are local to the identity that makes them. The name path \
             'me alice laptops' means: whoever I call alice, then whoever she \
             calls laptops. A name can refer to several subjects. A grant to \
             a name path lets the identities along the path decide who gets \
             the grant.",
        ],
    ),
    (
        "LEAF KEYS",
        &[
            "A leaf key is a key without a log. It uses ML-DSA-65 and Ed25519 \
             together, and both signatures must be valid. Leaf keys sign and \
             verify quickly, and every grant to a leaf key, or name for one, \
             expires within 24 hours. Use them for machines that sign often. \
             A signature by a leaf key verifies only while the leaf key's \
             grant is live.",
        ],
    ),
    (
        "TIME",
        &[
            "Each statement includes the time it was issued, as given by the \
             signer, and may carry an expiry time. writ does not accept a \
             statement issued more than 5 minutes in the future.",
            "writ reads the clock, but never uses a time before its build \
             date, or, with --state, before the newest statement seen from \
             the --as identities. So setting the clock back does not make \
             expired grants valid again. Setting it forward only makes grants \
             expire early.",
        ],
    ),
    (
        "SECRET KEYS",
        &[
            "A secret key file holds one line per key, starting with \
             WRIT-SECRET-KEY-1, after a line starting with # that says what \
             the key is and which identity it belongs to. The file is not \
             encrypted. writ creates key \
             files that only their owner can read, and never overwrites a \
             file: a path to write to must not exist yet. Commands that read \
             keys accept - (standard input) and /dev/fd/N. Commands that \
             write keys or other files accept - (standard output) and \
             /dev/fd/N, which writ opens for appending, so keys can stay \
             encrypted with age(1):",
            "    writ grant -i me --key <(age -d me.key.age) alice '(ssh)'",
        ],
    ),
    (
        "SECURITY",
        &[
            "writ has no network protocol. Verifiers learn about rotations and \
             revocations only from the bundles you give them. A verifier that \
             never sees your rotation keeps trusting your old current key, \
             including in the hands of a thief. --max-validity does not \
             change that: a thief who has the key can keep making new \
             statements. Give verifiers your newest bundle, and have them use \
             --state, so that once they see a rotation or a revocation they \
             never go back. The same goes for proofs: writ prove output holds \
             only what its sender chose, so check it with --state.",
            "If two different rotations of one identity appear, writ refuses \
             the identity: someone who holds its next keys signed both. writ \
             keeps refusing it (with --state) until you remove its file from \
             the state directory.",
        ],
    ),
];

/// FILES in writ(1).
pub static FILES: &[(&str, &str)] = &[
    ("DIR/log.writ", "the identity log"),
    (
        "DIR/issued.writ",
        "every statement and data signature the identity issued; read by \
         `writ rotate` and `writ export`",
    ),
    (
        "DIR/next.writ",
        "the public keys of every set of next keys the log has committed to",
    ),
    (
        "DIR/current.key",
        "the current secret key, unless you keep it somewhere else",
    ),
    (
        "DIR/record.writ",
        "the log and the newest revocation record, if the identity publishes them: \
         the file to publish",
    ),
    (
        "STATE/floor",
        "with --state: the clock floor, in seconds since 1970",
    ),
    (
        "STATE/logs/ID.writ",
        "with --state: the log, revocations and newest revocation records of \
         each identity a question relied on",
    ),
];

/// ENVIRONMENT in writ(1).
pub static ENVIRONMENT: &[(&str, &str)] = &[
    (
        "NO_COLOR",
        "if set and not empty, do not use color, unless --color=always",
    ),
    (
        "CLICOLOR_FORCE",
        "if set and not 0, use color even when output is not a terminal",
    ),
    ("TERM", "if dumb, do not use color"),
    ("COLUMNS", "the width to wrap help text to"),
];

/// EXIT STATUS, for every page.
pub static EXIT_STATUS: &[(&str, &str)] = &[
    ("0", "success; for questions, the answer is yes"),
    (
        "1",
        "the answer is no: the check, verification, proof or name lookup was \
         denied",
    ),
    (
        "2",
        "an error: bad usage, unreadable input, or a failed operation",
    ),
];

/// EXAMPLES in writ(1).
pub static TOUR: &[(&str, &str)] = &[
    (
        "Create two identities:",
        "writ init me --next-out - | age -p > me-next.key.age\nwrit init alice --next-out alice-next.key",
    ),
    (
        "Name alice, and let her log in to nas:",
        "writ name -i me alice alice >> bundle.writ\nwrit grant -i me 'me alice' '(ssh nas)' >> bundle.writ",
    ),
    (
        "Check, as nas would:",
        "writ check --as me alice '(ssh nas)' < bundle.writ",
    ),
];

/// STANDARDS in writ(1).
pub const STANDARDS: &str = "SLH-DSA (FIPS 205), ML-DSA (FIPS 204), Ed25519 (RFC 8032), SHA-3 and \
     SHAKE (FIPS 202), bech32m (BIP 350). The exact formats are in SPEC.md in \
     the writ source.";
