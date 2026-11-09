// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! SSH authentication policy for [`crate::ssh::SshTransport`].
//!
//! [`SshAuth`] configures the ordered authentication methods, key files,
//! password sources, and keyboard-interactive responder. The convenience
//! connection methods use [`SshAuth::legacy`]: agent, password, then `none`.
//! [`SshAuth::discovered`] also discovers key files and enables
//! keyboard-interactive authentication. Callers can restrict or reorder
//! methods to match their connection policy.
//!
//! # Why the responder is injected
//!
//! Keyboard-interactive is a conversation: the server sends prompts,
//! the client answers them.  Answering means either reading a terminal
//! or consulting something the caller already has.  A *library* must
//! not decide to grab stdin -- a simulator with a pixel display and a
//! TUI has no console to prompt on, and a headless regression run
//! would hang forever waiting for an answer nobody can type.  So the
//! caller supplies a [`KbdPrompt`]; with none supplied, non-echo
//! prompts are answered from `password` if it is set, and the method
//! is skipped entirely if it is not.
//!
//! # libssh2 and modern key files
//!
//! `PublicKey` auth goes through `libssh2_userauth_publickey_fromfile`,
//! which does **not** universally read the `-----BEGIN OPENSSH PRIVATE
//! KEY-----` container that `ssh-keygen` has produced by default since
//! OpenSSH 7.8.  A key that works fine with `/usr/bin/ssh` can be
//! rejected here.  That is a property of libssh2, not of the key, and
//! the two ways out are to load the key into an agent (which this
//! module tries first by default) or to convert a copy with
//! `ssh-keygen -p -m PEM -f <copy>`.  [`SshAuthError::advice`] says so
//! in the failure message rather than leaving the caller to guess.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ssh2::Session;

/// One SSH authentication method, in the sense of RFC 4252.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshAuthMethod {
    /// Ask a running `ssh-agent` / Pageant to sign for each identity it holds.
    Agent,
    /// Offer a private key file directly.
    PublicKey,
    /// The `password` method: a single secret sent in one message.
    Password,
    /// The `keyboard-interactive` method: a server-driven challenge/response
    /// exchange.  This is what a stock `sshd` with PAM usually offers, and it
    /// is *not* the same method as `password` even when the only challenge is
    /// the word "Password:".
    KeyboardInteractive,
    /// The `none` method: some servers accept it outright.  Probing it is also
    /// how a client learns which methods the server will accept at all.
    None,
}

impl SshAuthMethod {
    /// The spelling used in specs, messages, and `--auth` lists.
    pub fn as_str(self) -> &'static str {
        match self {
            SshAuthMethod::Agent => "agent",
            SshAuthMethod::PublicKey => "publickey",
            SshAuthMethod::Password => "password",
            SshAuthMethod::KeyboardInteractive => "keyboard-interactive",
            SshAuthMethod::None => "none",
        }
    }

    /// Parse one method name.  Accepts the OpenSSH spellings as well as the
    /// short forms a person actually types.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "agent" => Ok(SshAuthMethod::Agent),
            "publickey" | "pubkey" | "key" | "identity" => Ok(SshAuthMethod::PublicKey),
            "password" | "pass" => Ok(SshAuthMethod::Password),
            "keyboard-interactive" | "keyboard" | "interactive" | "kbdint" => {
                Ok(SshAuthMethod::KeyboardInteractive)
            }
            "none" => Ok(SshAuthMethod::None),
            other => Err(format!(
                "unknown ssh auth method '{}' (expected agent, publickey, password, \
                 keyboard-interactive, or none)",
                other
            )),
        }
    }

    /// Parse a comma-separated ordered list, e.g. `"agent,publickey,password"`.
    ///
    /// Empty entries are skipped so `"agent,,password"` and a trailing comma
    /// are both accepted, but a list that names nothing at all is an error --
    /// an empty ladder authenticates nothing and would otherwise fail later
    /// with a much less obvious message.
    pub fn parse_list(s: &str) -> Result<Vec<Self>, String> {
        let mut out = Vec::new();
        for part in s.split(',') {
            if part.trim().is_empty() {
                continue;
            }
            let m = Self::parse(part)?;
            if !out.contains(&m) {
                out.push(m);
            }
        }
        if out.is_empty() {
            return Err(format!("ssh auth list '{}' names no methods", s));
        }
        Ok(out)
    }
}

impl fmt::Display for SshAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Answers keyboard-interactive challenges on the caller's behalf.
///
/// `prompts` is a list of `(text, echo)` pairs; `echo == false` marks a
/// secret the terminal should not display.  Return exactly one response per
/// prompt -- libssh2 pairs them positionally, and a short vector is a
/// protocol error rather than a partial answer.
pub trait KbdPrompt: Send + Sync {
    /// Produce one response per prompt.
    fn respond(
        &self,
        username: &str,
        instructions: &str,
        prompts: &[(String, bool)],
    ) -> Vec<String>;
}

/// What to try, in what order, with what material.
#[derive(Clone)]
pub struct SshAuth {
    /// Methods to attempt, first to last.  The first one that authenticates
    /// wins; the rest are not attempted. Method discovery sends a `none`
    /// probe first; its success is accepted only when `None` is allowed.
    pub order: Vec<SshAuthMethod>,
    /// Private key files for [`SshAuthMethod::PublicKey`], tried in order.
    /// A `<path>.pub` sibling is passed alongside when it exists.
    pub identities: Vec<PathBuf>,
    /// Secret for [`SshAuthMethod::Password`], and the default answer to
    /// non-echo keyboard-interactive prompts when no [`KbdPrompt`] is set.
    pub password: Option<String>,
    /// Passphrase protecting the files in `identities`.
    pub passphrase: Option<String>,
    /// Answers keyboard-interactive challenges.  See the module docs for why
    /// this is injected rather than read from stdin.
    pub kbd_prompt: Option<Arc<dyn KbdPrompt>>,
}

// Passwords must not reach a log line through a stray `{:?}`.  Hand-written
// so that adding a secret-bearing field later cannot silently start printing
// it: every field is listed here explicitly.
impl fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshAuth")
            .field("order", &self.order)
            .field("identities", &self.identities)
            .field(
                "password",
                &self
                    .password
                    .as_ref()
                    .map(|_| "<redacted>")
                    .unwrap_or("None"),
            )
            .field(
                "passphrase",
                &self
                    .passphrase
                    .as_ref()
                    .map(|_| "<redacted>")
                    .unwrap_or("None"),
            )
            .field("kbd_prompt", &self.kbd_prompt.is_some())
            .finish()
    }
}

impl Default for SshAuth {
    /// Agent, key files, password, keyboard-interactive, then `none`.
    fn default() -> Self {
        Self {
            order: vec![
                SshAuthMethod::Agent,
                SshAuthMethod::PublicKey,
                SshAuthMethod::Password,
                SshAuthMethod::KeyboardInteractive,
                SshAuthMethod::None,
            ],
            identities: Vec::new(),
            password: None,
            passphrase: None,
            kbd_prompt: None,
        }
    }
}

impl SshAuth {
    /// Compatibility policy: agent, password from `TVI950_SSH_PASSWORD` /
    /// `S100BOX_SSH_PASSWORD`, then `none`.
    ///
    /// Used by `SshTransport::connect` and `connect_with_pty`.
    pub fn legacy() -> Self {
        Self {
            order: vec![
                SshAuthMethod::Agent,
                SshAuthMethod::Password,
                SshAuthMethod::None,
            ],
            identities: Vec::new(),
            password: password_from_env(&LEGACY_PASSWORD_VARS),
            passphrase: None,
            kbd_prompt: None,
        }
    }

    /// Default identities plus a password from the environment: what a
    /// general-purpose client should start from.
    pub fn discovered() -> Self {
        Self {
            identities: default_identities(),
            password: password_from_env(&DEFAULT_PASSWORD_VARS),
            ..Self::default()
        }
    }

    /// Restrict the ladder to a single method.  Use when the caller wants a
    /// definite failure rather than a silent fallback -- "it connected, but I
    /// don't know how" is not a useful outcome when you are testing auth.
    pub fn only(mut self, method: SshAuthMethod) -> Self {
        self.order = vec![method];
        self
    }
}

/// Password sources used by [`SshAuth::legacy`], in priority order.
pub const LEGACY_PASSWORD_VARS: [&str; 2] = ["TVI950_SSH_PASSWORD", "S100BOX_SSH_PASSWORD"];

/// Password sources for [`SshAuth::discovered`]: the shared name first,
/// followed by the per-simulator names.
pub const DEFAULT_PASSWORD_VARS: [&str; 3] = [
    "RETROSIM_SSH_PASSWORD",
    "TVI950_SSH_PASSWORD",
    "S100BOX_SSH_PASSWORD",
];

/// First non-empty value among `vars`.
///
/// Empty is treated as unset on purpose: an exported-but-blank variable is
/// how a shell script signals "I have no password", and offering the empty
/// string can consume a server's limited authentication attempts before other
/// methods get their turn.
pub fn password_from_env(vars: &[&str]) -> Option<String> {
    vars.iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|s| !s.is_empty())
}

/// Conventional private key files under `~/.ssh`, in preference order,
/// filtered to those that exist.
pub fn default_identities() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    ["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"]
        .iter()
        .map(|n| home.join(".ssh").join(n))
        .filter(|p| p.is_file())
        .collect()
}

/// The user's home directory.
///
/// `USERPROFILE` first, then `HOME`: on Windows under Git Bash BOTH are set,
/// and `HOME` is the MSYS view (`/c/Users/x`, or sometimes a `/home/x` that
/// does not exist in the Win32 namespace).  libssh2 opens key files through
/// the Win32 API, which cannot follow an MSYS path, so preferring
/// `USERPROFILE` is what makes `~/.ssh/id_ed25519` resolve to a path the
/// library can actually open.
pub(crate) fn home_dir() -> Option<PathBuf> {
    for var in ["USERPROFILE", "HOME"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                let p = PathBuf::from(v);
                if p.is_dir() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Why authentication failed, with enough detail to act on.
#[derive(Debug, Clone)]
pub struct SshAuthError {
    /// The user the attempts were made for.
    pub user: String,
    /// The methods the server said it would accept, if it told us.
    pub server_offers: Option<String>,
    /// One `(method, error)` pair per attempt that was made and failed.
    pub attempts: Vec<(SshAuthMethod, String)>,
    /// Methods in the ladder that were skipped for want of material, with the
    /// reason -- "no password was supplied" is a different problem from "the
    /// password was wrong", and only one of them is fixed by retyping it.
    pub skipped: Vec<(SshAuthMethod, String)>,
    /// Where the attempts were made, once someone who knows fills it in.
    /// [`authenticate`] does not know the address it is speaking over, so
    /// this stays `None` until the caller sets it with [`Self::with_target`].
    pub target: Option<String>,
}

impl SshAuthError {
    /// Record the address these attempts were made against.
    ///
    /// The target belongs on the summary line beside the user. Keep it
    /// separate from advice about local actions such as key conversion.
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// A remedy suggestion chosen from what actually happened.
    pub fn advice(&self) -> Option<String> {
        let offers = self.server_offers.as_deref().unwrap_or("");
        let tried = |m: SshAuthMethod| self.attempts.iter().any(|(a, _)| *a == m);

        if tried(SshAuthMethod::PublicKey) {
            return Some(
                "a key file that works with /usr/bin/ssh can still be refused here: libssh2 \
                 does not read every `BEGIN OPENSSH PRIVATE KEY` container. Load the key into \
                 an agent, or convert a COPY with `ssh-keygen -p -m PEM -f <copy>`"
                    .to_string(),
            );
        }
        if offers.contains("keyboard-interactive")
            && !tried(SshAuthMethod::KeyboardInteractive)
            && !offers.contains("password")
        {
            return Some(
                "the server offers keyboard-interactive but not password; those are different \
                 methods. Add keyboard-interactive to the auth order"
                    .to_string(),
            );
        }
        if offers.contains("publickey") && !tried(SshAuthMethod::PublicKey) {
            return Some(
                "the server offers publickey but no identity file was found or supplied; name \
                 one explicitly, or start an agent that holds the key"
                    .to_string(),
            );
        }
        None
    }
}

impl fmt::Display for SshAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ssh authentication failed for user '{}'", self.user)?;
        if let Some(target) = &self.target {
            write!(f, " on {}", target)?;
        }
        if let Some(offers) = &self.server_offers {
            write!(f, " (server offers: {})", offers)?;
        }
        for (m, e) in &self.attempts {
            write!(f, "\n  {:<21} tried, failed: {}", m.as_str(), e)?;
        }
        for (m, why) in &self.skipped {
            write!(f, "\n  {:<21} skipped: {}", m.as_str(), why)?;
        }
        if let Some(advice) = self.advice() {
            write!(f, "\n  hint: {}", advice)?;
        }
        Ok(())
    }
}

/// Run the ladder in `auth` against `session`, returning the method that won.
///
/// Stops at the first success.  A method with nothing to work with -- no
/// password for `Password`, no identity file for `PublicKey` -- is recorded in
/// `skipped` and passed over rather than attempted, so it does not consume one
/// of the server's limited authentication tries.
pub fn authenticate(
    session: &Session,
    user: &str,
    auth: &SshAuth,
) -> Result<SshAuthMethod, SshAuthError> {
    // `auth_methods` is libssh2's `userauth_list`, which performs a `none`
    // authentication request as a side effect.  If the server accepts `none`
    // outright it returns an error whose real meaning is "you are already in",
    // which is why `authenticated()` is checked before the error is.
    let server_offers = match session.auth_methods(user) {
        Ok(list) => Some(list.to_string()),
        Err(_) => None,
    };
    let mut err = SshAuthError {
        user: user.to_string(),
        server_offers,
        attempts: Vec::new(),
        skipped: Vec::new(),
        target: None,
    };

    if session.authenticated() {
        if auth.order.contains(&SshAuthMethod::None) {
            return Ok(SshAuthMethod::None);
        }
        err.attempts.push((
            SshAuthMethod::None,
            "server accepted discovery without credentials, but policy disallows none".into(),
        ));
        return Err(err);
    }

    for &method in &auth.order {
        match method {
            SshAuthMethod::Agent => match try_agent(session, user) {
                Ok(true) => return Ok(method),
                Ok(false) => err
                    .skipped
                    .push((method, "no agent, or the agent holds no identities".into())),
                Err(e) => err.attempts.push((method, e)),
            },
            SshAuthMethod::PublicKey => {
                if auth.identities.is_empty() {
                    err.skipped
                        .push((method, "no identity file supplied or discovered".into()));
                    continue;
                }
                let mut any = false;
                for key in &auth.identities {
                    match try_pubkey(session, user, key, auth.passphrase.as_deref()) {
                        Ok(true) => return Ok(method),
                        Ok(false) => {}
                        Err(e) => {
                            any = true;
                            err.attempts
                                .push((method, format!("{}: {}", key.display(), e)));
                        }
                    }
                }
                if !any {
                    err.skipped
                        .push((method, "every identity file was unreadable".into()));
                }
            }
            SshAuthMethod::Password => match &auth.password {
                Some(pw) => match session.userauth_password(user, pw) {
                    Ok(()) if session.authenticated() => return Ok(method),
                    Ok(()) => err.attempts.push((
                        method,
                        "server accepted the message but not the session".into(),
                    )),
                    Err(e) => err.attempts.push((method, e.to_string())),
                },
                None => err.skipped.push((
                    method,
                    format!(
                        "no password supplied (set one of {})",
                        DEFAULT_PASSWORD_VARS.join(", ")
                    ),
                )),
            },
            SshAuthMethod::KeyboardInteractive => {
                match try_keyboard_interactive(session, user, auth) {
                    Ok(true) => return Ok(method),
                    Ok(false) => err.skipped.push((
                        method,
                        "no responder and no password to answer challenges with".into(),
                    )),
                    Err(e) => {
                        err.attempts.push((method, e));
                        // A malformed callback is still an error even if the
                        // server accepts the placeholder replies.
                        if session.authenticated() {
                            return Err(err);
                        }
                    }
                }
            }
            SshAuthMethod::None => {
                // The `none` probe already happened above via `auth_methods`;
                // reaching here means it did not authenticate us.
                err.skipped
                    .push((method, "the server did not accept `none`".into()));
            }
        }
    }

    Err(err)
}

fn try_agent(session: &Session, user: &str) -> Result<bool, String> {
    let mut agent = match session.agent() {
        Ok(a) => a,
        Err(e) => return Err(e.to_string()),
    };
    if agent.connect().is_err() {
        return Ok(false);
    }
    if agent.list_identities().is_err() {
        return Ok(false);
    }
    let identities = match agent.identities() {
        Ok(i) => i,
        Err(e) => return Err(e.to_string()),
    };
    if identities.is_empty() {
        return Ok(false);
    }
    let mut last = String::from("the agent offered no identity the server would accept");
    for identity in &identities {
        match agent.userauth(user, identity) {
            Ok(()) if session.authenticated() => return Ok(true),
            Ok(()) => {}
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

fn try_pubkey(
    session: &Session,
    user: &str,
    key: &Path,
    passphrase: Option<&str>,
) -> Result<bool, String> {
    if !key.is_file() {
        return Ok(false);
    }
    // libssh2 can derive the public half from most private keys, but not from
    // every format; hand it the `.pub` sibling when one is sitting right there.
    let pubkey = public_key_file(key);
    match session.userauth_pubkey_file(user, pubkey.as_deref(), key, passphrase) {
        Ok(()) if session.authenticated() => Ok(true),
        Ok(()) => Err("server accepted the key message but not the session".into()),
        Err(e) => Err(e.to_string()),
    }
}

fn public_key_file(key: &Path) -> Option<PathBuf> {
    // Append to the native path, preserving extensions and non-UTF-8 names.
    // Replacing `.pem` with `.pub` can select another identity's public key.
    let mut path = key.as_os_str().to_os_string();
    path.push(".pub");
    let path = PathBuf::from(path);
    path.is_file().then_some(path)
}

/// Bridges libssh2's prompt callback to the caller's [`KbdPrompt`], falling
/// back to `password` for non-echo prompts when no responder is set.
struct Responder<'a> {
    inner: Option<&'a dyn KbdPrompt>,
    password: Option<&'a str>,
    invalid_response: bool,
}

impl ssh2::KeyboardInteractivePrompt for Responder<'_> {
    fn prompt<'b>(
        &mut self,
        username: &str,
        instructions: &str,
        prompts: &[ssh2::Prompt<'b>],
    ) -> Vec<String> {
        let pairs: Vec<(String, bool)> = prompts
            .iter()
            .map(|p| (p.text.to_string(), p.echo))
            .collect();
        if let Some(inner) = self.inner {
            let answers = inner.respond(username, instructions, &pairs);
            if answers.len() != prompts.len() {
                self.invalid_response = true;
                // The FFI callback cannot return Result. Send no secrets and
                // report the contract error when libssh2 returns to Rust.
                return vec![String::new(); prompts.len()];
            }
            return answers;
        }
        pairs
            .iter()
            .map(|(_, echo)| {
                if *echo {
                    String::new()
                } else {
                    self.password.unwrap_or_default().to_string()
                }
            })
            .collect()
    }
}

fn try_keyboard_interactive(session: &Session, user: &str, auth: &SshAuth) -> Result<bool, String> {
    if auth.kbd_prompt.is_none() && auth.password.is_none() {
        return Ok(false);
    }
    let mut responder = Responder {
        inner: auth.kbd_prompt.as_deref(),
        password: auth.password.as_deref(),
        invalid_response: false,
    };
    let result = session.userauth_keyboard_interactive(user, &mut responder);
    if responder.invalid_response {
        return Err(
            "keyboard-interactive responder must return exactly one answer per prompt".into(),
        );
    }
    match result {
        Ok(()) if session.authenticated() => Ok(true),
        Ok(()) => Err("server accepted challenge replies but not the session".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responder_rejects_both_short_and_long_answer_vectors() {
        use ssh2::KeyboardInteractivePrompt;
        struct Answers(usize);
        impl KbdPrompt for Answers {
            fn respond(&self, _: &str, _: &str, _: &[(String, bool)]) -> Vec<String> {
                vec!["secret".into(); self.0]
            }
        }
        let prompts = [ssh2::Prompt {
            text: "Password".into(),
            echo: false,
        }];
        for count in [0, 2] {
            let answers = Answers(count);
            let mut responder = Responder {
                inner: Some(&answers),
                password: None,
                invalid_response: false,
            };
            assert_eq!(responder.prompt("user", "", &prompts), [""]);
            assert!(responder.invalid_response);
        }
        let mut responder = Responder {
            inner: None,
            password: Some("secret"),
            invalid_response: false,
        };
        assert_eq!(responder.prompt("user", "", &prompts), ["secret"]);
        assert!(!responder.invalid_response);
    }

    #[test]
    fn a_public_key_sidecar_appends_to_the_entire_private_key_name() {
        let dir =
            std::env::temp_dir().join(format!("retrosim-auth-sidecar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let private = dir.join("identity.pem");
        let sidecar = dir.join("identity.pem.pub");
        let unrelated = dir.join("identity.pub");
        std::fs::write(&sidecar, "matching public key").unwrap();
        std::fs::write(&unrelated, "another identity").unwrap();
        assert_eq!(public_key_file(&private), Some(sidecar.clone()));
        std::fs::remove_file(&sidecar).unwrap();
        assert_eq!(public_key_file(&private), None);
        std::fs::remove_file(&unrelated).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn method_names_round_trip() {
        for m in [
            SshAuthMethod::Agent,
            SshAuthMethod::PublicKey,
            SshAuthMethod::Password,
            SshAuthMethod::KeyboardInteractive,
            SshAuthMethod::None,
        ] {
            assert_eq!(SshAuthMethod::parse(m.as_str()).unwrap(), m);
        }
    }

    #[test]
    fn method_short_forms_parse() {
        assert_eq!(
            SshAuthMethod::parse("pubkey").unwrap(),
            SshAuthMethod::PublicKey
        );
        assert_eq!(
            SshAuthMethod::parse("  KEY  ").unwrap(),
            SshAuthMethod::PublicKey
        );
        assert_eq!(
            SshAuthMethod::parse("kbdint").unwrap(),
            SshAuthMethod::KeyboardInteractive
        );
    }

    #[test]
    fn unknown_method_names_itself_in_the_error() {
        let e = SshAuthMethod::parse("kerberos").unwrap_err();
        assert!(e.contains("kerberos"), "{}", e);
    }

    #[test]
    fn list_preserves_order_and_dedupes() {
        let l = SshAuthMethod::parse_list("password,agent,password").unwrap();
        assert_eq!(
            l,
            vec![SshAuthMethod::Password, SshAuthMethod::Agent],
            "first occurrence wins and the duplicate is dropped"
        );
    }

    #[test]
    fn list_tolerates_stray_commas() {
        let l = SshAuthMethod::parse_list("agent,,password,").unwrap();
        assert_eq!(l, vec![SshAuthMethod::Agent, SshAuthMethod::Password]);
    }

    #[test]
    fn empty_list_is_an_error_not_an_empty_ladder() {
        // A silently-empty ladder would authenticate nothing and report it
        // somewhere far away from the typo that caused it.
        assert!(SshAuthMethod::parse_list(",,,").is_err());
        assert!(SshAuthMethod::parse_list("").is_err());
    }

    #[test]
    fn legacy_ladder_uses_agent_password_and_none() {
        let a = SshAuth::legacy();
        assert_eq!(
            a.order,
            vec![
                SshAuthMethod::Agent,
                SshAuthMethod::Password,
                SshAuthMethod::None
            ]
        );
        assert!(
            a.identities.is_empty(),
            "the legacy policy must not discover key files"
        );
    }

    #[test]
    fn default_ladder_leads_with_agent_and_ends_with_none() {
        let a = SshAuth::default();
        assert_eq!(a.order.first(), Some(&SshAuthMethod::Agent));
        assert_eq!(a.order.last(), Some(&SshAuthMethod::None));
    }

    #[test]
    fn only_restricts_the_ladder_to_one_method() {
        let a = SshAuth::default().only(SshAuthMethod::Password);
        assert_eq!(a.order, vec![SshAuthMethod::Password]);
    }

    #[test]
    fn debug_redacts_secrets() {
        let a = SshAuth {
            password: Some("hunter2".into()),
            passphrase: Some("swordfish".into()),
            ..SshAuth::default()
        };
        let s = format!("{:?}", a);
        assert!(!s.contains("hunter2"), "password leaked into Debug: {}", s);
        assert!(
            !s.contains("swordfish"),
            "passphrase leaked into Debug: {}",
            s
        );
        assert!(s.contains("redacted"), "{}", s);
    }

    #[test]
    fn empty_env_password_counts_as_unset() {
        // Guard the "exported but blank" case: offering "" to the server
        // burns one of a small number of allowed attempts.
        std::env::set_var("RETROSIM_TEST_PW_EMPTY", "");
        std::env::set_var("RETROSIM_TEST_PW_SET", "real");
        let got = password_from_env(&["RETROSIM_TEST_PW_EMPTY", "RETROSIM_TEST_PW_SET"]);
        assert_eq!(got.as_deref(), Some("real"));
        std::env::remove_var("RETROSIM_TEST_PW_EMPTY");
        std::env::remove_var("RETROSIM_TEST_PW_SET");
    }

    #[test]
    fn missing_env_password_is_none() {
        assert_eq!(password_from_env(&["RETROSIM_TEST_PW_ABSENT_XYZ"]), None);
    }

    /// Target addresses stay on the summary line; key-conversion advice is local.
    #[test]
    fn target_lands_on_the_summary_line_not_after_the_hint() {
        let e = SshAuthError {
            user: "hharte".into(),
            server_offers: Some("publickey,password".into()),
            attempts: vec![(SshAuthMethod::PublicKey, "Callback returned error".into())],
            skipped: vec![],
            target: None,
        }
        .with_target("192.168.1.42:22");

        let s = e.to_string();
        let first = s.lines().next().unwrap();
        assert!(
            first.contains("192.168.1.42:22"),
            "address belongs on the summary line, got: {first}"
        );
        // The target must not qualify the local key-conversion hint.
        let hint = s.lines().find(|l| l.contains("hint:")).unwrap();
        assert!(
            !hint.contains("192.168.1.42"),
            "the hint must not name the server: the ssh-keygen conversion is              local, got: {hint}"
        );
    }

    #[test]
    fn error_display_names_every_attempt_and_skip() {
        let e = SshAuthError {
            user: "hharte".into(),
            server_offers: Some("publickey,password".into()),
            attempts: vec![(SshAuthMethod::Password, "Authentication failed".into())],
            skipped: vec![(SshAuthMethod::Agent, "no agent".into())],
            target: None,
        };
        let s = e.to_string();
        assert!(s.contains("hharte"));
        assert!(s.contains("publickey,password"));
        assert!(s.contains("Authentication failed"));
        assert!(s.contains("no agent"));
    }

    #[test]
    fn advice_points_at_libssh2_when_a_key_was_actually_tried() {
        let e = SshAuthError {
            user: "u".into(),
            server_offers: Some("publickey".into()),
            attempts: vec![(
                SshAuthMethod::PublicKey,
                "Unable to extract public key".into(),
            )],
            skipped: vec![],
            target: None,
        };
        let a = e.advice().expect("a tried-and-failed key deserves advice");
        assert!(a.contains("PEM"), "{}", a);
    }

    #[test]
    fn advice_distinguishes_keyboard_interactive_from_password() {
        // The failure mode this exists for: sshd offers only
        // keyboard-interactive, the caller supplied a password, and the
        // password method was never offered -- so "wrong password" is the
        // wrong conclusion.
        let e = SshAuthError {
            user: "u".into(),
            server_offers: Some("keyboard-interactive".into()),
            attempts: vec![(SshAuthMethod::Password, "no".into())],
            skipped: vec![],
            target: None,
        };
        let a = e.advice().expect("should advise");
        assert!(a.contains("keyboard-interactive"), "{}", a);
    }

    #[test]
    fn advice_is_silent_when_nothing_useful_can_be_said() {
        let e = SshAuthError {
            user: "u".into(),
            server_offers: None,
            attempts: vec![(SshAuthMethod::Agent, "refused".into())],
            skipped: vec![],
            target: None,
        };
        assert!(e.advice().is_none());
    }

    #[test]
    fn discovered_identities_all_exist() {
        // Offering a path that is not there wastes an attempt and produces a
        // confusing "unable to open" in the failure list.
        for p in default_identities() {
            assert!(p.is_file(), "{} was listed but does not exist", p.display());
        }
    }
}
