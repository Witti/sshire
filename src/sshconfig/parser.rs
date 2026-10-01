//! Small, read-only parser for the ssh config (`~/.ssh/config`).
//!
//! Supported are `Host` blocks, `Include` (globs, recursive) and the fields
//! HostName, User, Port, IdentityFile and ProxyJump. `Match` blocks and host
//! patterns with wildcards/negation are skipped.
//!
//! The parser only opens files for reading; nothing is written.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Maximum nesting depth of `Include` (protection against infinite loops).
const MAX_INCLUDE_DEPTH: usize = 16;

/// A concrete host entry (alias without wildcards) including its options.
// `Default` fills all fields with their default value (`None`, empty string).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedHost {
    /// The alias as it appears after `Host`.
    pub alias: String,
    /// Value of `HostName`.
    pub hostname: Option<String>,
    /// Value of `User`.
    pub user: Option<String>,
    /// Value of `Port`.
    pub port: Option<u16>,
    /// First `IdentityFile` value (with `~` expanded).
    pub identity_file: Option<String>,
    /// Value of `ProxyJump`.
    pub proxy_jump: Option<String>,
}

/// Result of parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedConfig {
    /// Hosts in the order of their first definition.
    pub hosts: Vec<ParsedHost>,
    /// Non-fatal problems (unreadable file, invalid port, …).
    pub warnings: Vec<String>,
    /// `true` if an existing file could not be read. In that case hosts may
    /// be missing, and the sync must not archive anything.
    pub incomplete: bool,
}

/// Parses the config file `main_path`; `home` is used for `~` expansion and
/// as the base (`<home>/.ssh`) for relative `Include` paths.
///
/// A missing main file yields an empty list without an error.
pub fn parse_config(main_path: &Path, home: &Path) -> ParsedConfig {
    let mut parser = Parser::new(home);
    parser.read_file(main_path, 0);
    parser.finish()
}

/// State during parsing.
///
/// Instead of return values, the parser collects everything in this struct;
/// the recursive method `read_file` takes `&mut self` and modifies the state
/// directly (one owner, always only *one* mutable reference).
struct Parser {
    home: PathBuf,
    ssh_dir: PathBuf,
    hosts: Vec<ParsedHost>,
    /// Alias -> index into `hosts` (for "first wins" + filling in fields).
    index: HashMap<String, usize>,
    warnings: Vec<String>,
    incomplete: bool,
    /// Files that are currently open (cycle protection).
    active_files: HashSet<PathBuf>,
    /// Indices of the hosts of the current `Host` block. Empty = global, `Match`
    /// or wildcards only: options are ignored then.
    current: Vec<usize>,
}

impl Parser {
    fn new(home: &Path) -> Self {
        Parser {
            home: home.to_path_buf(),
            ssh_dir: home.join(".ssh"),
            hosts: Vec::new(),
            index: HashMap::new(),
            warnings: Vec::new(),
            incomplete: false,
            active_files: HashSet::new(),
            current: Vec::new(),
        }
    }

    // `self` (not `&self`): consumes the parser and hands out its parts without
    // copying (ownership moves into the result).
    fn finish(self) -> ParsedConfig {
        ParsedConfig {
            hosts: self.hosts,
            warnings: self.warnings,
            incomplete: self.incomplete,
        }
    }

    /// Reads a file and processes it line by line. Recursive for `Include`.
    fn read_file(&mut self, path: &Path, depth: usize) {
        if depth > MAX_INCLUDE_DEPTH {
            self.warnings.push(format!(
                "Include depth exceeds {MAX_INCLUDE_DEPTH} at {} – ignored",
                path.display()
            ));
            return;
        }
        // The canonical path resolves symlinks/`..` so the same file is detected
        // as a cycle even when spelled differently. If that fails (file
        // missing), we use the path unchanged.
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        // `insert` returns `false` if the value was already present.
        if !self.active_files.insert(key.clone()) {
            self.warnings
                .push(format!("Include cycle at {} – ignored", path.display()));
            return;
        }

        match std::fs::read(path) {
            // Invalid UTF-8 is replaced instead of aborting.
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                // The block membership before an include is preserved afterwards:
                // hosts from the included file only take effect there.
                let saved = self.current.clone();
                self.parse_text(&text, depth);
                if depth > 0 {
                    self.current = saved;
                }
            }
            // A missing file is normal (e.g. no ~/.ssh/config).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                self.incomplete = true;
                self.warnings
                    .push(format!("{} not readable: {e}", path.display()));
            }
        }
        self.active_files.remove(&key);
    }

    /// Processes the contents of a file line by line.
    fn parse_text(&mut self, text: &str, depth: usize) {
        // `lines()` is an iterator over the lines (without line endings; `\r\n`
        // is stripped too). No copies are made: each `line` is a `&str` slice
        // of `text`.
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (keyword, rest) = split_keyword(line);
            let args = split_args(rest);
            match keyword.to_ascii_lowercase().as_str() {
                "host" => self.start_host_block(&args),
                "match" => self.current.clear(),
                "include" => self.include(&args, depth),
                "hostname" | "user" | "port" | "identityfile" | "proxyjump" => {
                    // `first()` returns `Option<&String>`; without a value: ignore.
                    if let Some(value) = args.first() {
                        self.apply_option(&keyword.to_ascii_lowercase(), value);
                    }
                }
                _ => {}
            }
        }
    }

    /// Starts a `Host` block: creates entries for all concrete aliases.
    fn start_host_block(&mut self, patterns: &[String]) {
        self.current.clear();
        for pattern in patterns {
            if pattern.is_empty() || pattern.contains(['*', '?', '!']) {
                continue;
            }
            // `entry` + index: if the alias already exists, its entry is reused
            // (first wins, gaps are filled in).
            let idx = match self.index.get(pattern) {
                Some(&i) => i,
                None => {
                    self.hosts.push(ParsedHost {
                        alias: pattern.clone(),
                        ..ParsedHost::default()
                    });
                    self.index.insert(pattern.clone(), self.hosts.len() - 1);
                    self.hosts.len() - 1
                }
            };
            self.current.push(idx);
        }
    }

    /// Sets an option for all hosts of the current block – only if it is still
    /// empty there (as with ssh, the first value wins).
    fn apply_option(&mut self, key: &str, value: &str) {
        if self.current.is_empty() {
            return;
        }
        // Check the port once up front so the warning only appears once.
        let port = if key == "port" {
            match value.parse::<u16>() {
                Ok(p) => Some(p),
                Err(_) => {
                    self.warnings
                        .push(format!("Invalid port \"{value}\" – ignored"));
                    return;
                }
            }
        } else {
            None
        };
        for &i in &self.current {
            let host = &mut self.hosts[i];
            // `get_or_insert_with` only sets the value if the option is `None`;
            // the closure therefore only runs when needed.
            match key {
                "hostname" => {
                    host.hostname.get_or_insert_with(|| value.to_string());
                }
                "user" => {
                    host.user.get_or_insert_with(|| value.to_string());
                }
                "port" => host.port = host.port.or(port),
                "identityfile" => {
                    host.identity_file
                        .get_or_insert_with(|| expand_tilde(value, &self.home));
                }
                "proxyjump" => {
                    host.proxy_jump.get_or_insert_with(|| value.to_string());
                }
                _ => {}
            }
        }
    }

    /// Processes an `Include` line (multiple arguments, globs).
    fn include(&mut self, patterns: &[String], depth: usize) {
        for pattern in patterns {
            let expanded = expand_tilde(pattern, &self.home);
            let full = if Path::new(&expanded).is_absolute() {
                expanded
            } else {
                // Relative paths are relative to ~/.ssh. Special characters in the
                // directory part are escaped so they aren't treated as a glob.
                format!(
                    "{}/{}",
                    glob::Pattern::escape(&self.ssh_dir.to_string_lossy()),
                    expanded
                )
            };
            // Invalid glob pattern or match error: ignore silently.
            let Ok(paths) = glob::glob(&full) else {
                continue;
            };
            // `flatten()` skips the `Err` entries of the iterator.
            // The `glob` crate returns matches sorted alphabetically.
            let files: Vec<PathBuf> = paths.flatten().filter(|p| p.is_file()).collect();
            for file in files {
                self.read_file(&file, depth + 1);
            }
        }
    }
}

/// Splits keyword and rest of a line. Separator: whitespace or `=`
/// (also with spaces around it, e.g. `Port = 22`).
fn split_keyword(line: &str) -> (&str, &str) {
    // `find` with a closure returns the byte position of the first separator.
    // `unwrap_or(line.len())`: no separator -> the whole line is the keyword.
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    // Slicing `&line[..end]` creates a view, not a copy. This is safe because
    // `find` only returns character boundaries.
    let (keyword, rest) = (&line[..end], line[end..].trim_start());
    // At most one `=` is part of the separator.
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    (keyword, rest)
}

/// Splits arguments on whitespace; `"…"` keeps spaces together.
/// An unquoted token starting with `#` begins a comment.
fn split_args(rest: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    // Has a character (or `""`) been collected yet? Needed so that `""` yields
    // an empty argument.
    let mut has_token = false;

    for c in rest.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    args.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            '#' if !in_quotes && !has_token => break,
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(current);
    }
    args
}

/// Replaces a leading `~` or `~/` with the home directory.
fn expand_tilde(value: &str, home: &Path) -> String {
    if value == "~" {
        home.to_string_lossy().into_owned()
    } else if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest).to_string_lossy().into_owned()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Temporary home directory, deleted when dropped.
    /// Tests only write here – never into the real `~/.ssh`.
    struct TempHome(PathBuf);

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    impl TempHome {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir().join(format!("sshire-t3-{}-{n}", std::process::id()));
            fs::create_dir_all(dir.join(".ssh")).unwrap();
            TempHome(dir)
        }
        /// Writes a file relative to `~/.ssh`.
        fn write(&self, rel: &str, content: &str) -> PathBuf {
            let path = self.0.join(".ssh").join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            path
        }
        fn parse(&self) -> ParsedConfig {
            parse_config(&self.0.join(".ssh").join("config"), &self.0)
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn parse_str(text: &str) -> ParsedConfig {
        let home = TempHome::new();
        home.write("config", text);
        home.parse()
    }

    fn aliases(cfg: &ParsedConfig) -> Vec<&str> {
        cfg.hosts.iter().map(|h| h.alias.as_str()).collect()
    }

    #[test]
    fn missing_main_file_is_empty_without_warning() {
        let home = TempHome::new();
        let cfg = home.parse();
        assert!(cfg.hosts.is_empty());
        assert!(cfg.warnings.is_empty());
        assert!(!cfg.incomplete);
    }

    #[test]
    fn basic_block_with_all_fields() {
        let cfg = parse_str(
            "# Comment\n\nHost web\n  HostName web.example.com\n  User deploy\n  Port 2222\n  \
             IdentityFile /keys/id\n  ProxyJump bastion\n",
        );
        assert_eq!(
            cfg.hosts,
            vec![ParsedHost {
                alias: "web".into(),
                hostname: Some("web.example.com".into()),
                user: Some("deploy".into()),
                port: Some(2222),
                identity_file: Some("/keys/id".into()),
                proxy_jump: Some("bastion".into()),
            }]
        );
    }

    #[test]
    fn multiple_patterns_become_separate_entries() {
        let cfg = parse_str("Host a b c\n  User root\n");
        assert_eq!(aliases(&cfg), ["a", "b", "c"]);
        assert!(cfg.hosts.iter().all(|h| h.user.as_deref() == Some("root")));
    }

    #[test]
    fn wildcards_and_negation_are_skipped() {
        let cfg = parse_str("Host *\n  User x\nHost web-* db? !bad ok\n  User y\n");
        assert_eq!(aliases(&cfg), ["ok"]);
        assert_eq!(cfg.hosts[0].user.as_deref(), Some("y"));
    }

    #[test]
    fn equals_syntax_and_case_insensitive_keywords() {
        let cfg = parse_str("HOST=web\n  hostname = web.example.com\n  PORT=22\n  uSeR   bob\n");
        let h = &cfg.hosts[0];
        assert_eq!(h.alias, "web");
        assert_eq!(h.hostname.as_deref(), Some("web.example.com"));
        assert_eq!(h.port, Some(22));
        assert_eq!(h.user.as_deref(), Some("bob"));
    }

    #[test]
    fn quoted_values_keep_spaces() {
        let cfg = parse_str("Host \"my box\" other\n  IdentityFile \"/path with space/id\"\n");
        assert_eq!(aliases(&cfg), ["my box", "other"]);
        assert_eq!(
            cfg.hosts[0].identity_file.as_deref(),
            Some("/path with space/id")
        );
    }

    #[test]
    fn match_blocks_are_skipped() {
        let cfg = parse_str(
            "Host a\n  User one\nMatch host foo\n  User two\n  Port 1\nHost b\n  User three\n",
        );
        assert_eq!(aliases(&cfg), ["a", "b"]);
        assert_eq!(cfg.hosts[0].user.as_deref(), Some("one"));
        assert_eq!(cfg.hosts[0].port, None);
        assert_eq!(cfg.hosts[1].user.as_deref(), Some("three"));
    }

    #[test]
    fn first_value_wins_and_later_blocks_fill_gaps() {
        let cfg = parse_str(
            "Host a\n  User first\n  User second\nHost a\n  User third\n  Port 99\n  \
             HostName h\n",
        );
        assert_eq!(cfg.hosts.len(), 1);
        let h = &cfg.hosts[0];
        assert_eq!(h.user.as_deref(), Some("first"));
        assert_eq!(h.port, Some(99));
        assert_eq!(h.hostname.as_deref(), Some("h"));
    }

    #[test]
    fn tilde_is_expanded_in_identity_file() {
        let home = TempHome::new();
        home.write("config", "Host a\n  IdentityFile ~/.ssh/id_ed25519\n");
        let cfg = home.parse();
        let expected = home.0.join(".ssh/id_ed25519");
        assert_eq!(
            cfg.hosts[0].identity_file.as_deref(),
            Some(expected.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn invalid_port_yields_warning_not_failure() {
        let cfg = parse_str("Host a\n  Port abc\n  Port 70000\n  User u\n");
        assert_eq!(cfg.hosts[0].port, None);
        assert_eq!(cfg.hosts[0].user.as_deref(), Some("u"));
        assert_eq!(cfg.warnings.len(), 2);
    }

    #[test]
    fn include_with_glob_and_relative_path() {
        let home = TempHome::new();
        home.write(
            "config",
            "Include conf.d/*.conf extra\nHost main\n  User m\n",
        );
        home.write("conf.d/b.conf", "Host b\n  User b\n");
        home.write("conf.d/a.conf", "Host a\n  User a\n");
        home.write("conf.d/ignored.txt", "Host nope\n");
        home.write("extra", "Host e\n");
        let cfg = home.parse();
        assert_eq!(aliases(&cfg), ["a", "b", "e", "main"]);
    }

    #[test]
    fn include_absolute_and_tilde_paths() {
        let home = TempHome::new();
        let abs = home.write("abs.conf", "Host abs\n");
        home.write("tilde.conf", "Host til\n");
        home.write(
            "config",
            &format!("Include {}\nInclude ~/.ssh/tilde.conf\n", abs.display()),
        );
        assert_eq!(aliases(&home.parse()), ["abs", "til"]);
    }

    #[test]
    fn include_cycle_is_detected() {
        let home = TempHome::new();
        home.write("config", "Include a.conf\nHost main\n");
        home.write("a.conf", "Host a\nInclude b.conf\n");
        home.write("b.conf", "Host b\nInclude a.conf\nInclude config\n");
        let cfg = home.parse();
        assert_eq!(aliases(&cfg), ["a", "b", "main"]);
        assert!(cfg.warnings.iter().any(|w| w.contains("cycle")));
    }

    #[test]
    fn missing_include_is_ignored_silently() {
        let cfg = parse_str("Include does-not-exist/*\nInclude nofile\nHost a\n");
        assert_eq!(aliases(&cfg), ["a"]);
        assert!(cfg.warnings.is_empty());
    }

    #[test]
    fn include_inside_host_block_applies_to_that_block() {
        let home = TempHome::new();
        home.write("config", "Host a\n  Include opts\n  HostName h\nHost b\n");
        home.write("opts", "User fromopts\n");
        let cfg = home.parse();
        assert_eq!(cfg.hosts[0].user.as_deref(), Some("fromopts"));
        assert_eq!(cfg.hosts[0].hostname.as_deref(), Some("h"));
        assert_eq!(cfg.hosts[1].user, None);
    }

    #[test]
    fn include_depth_is_limited() {
        let home = TempHome::new();
        // Chain c0 -> c1 -> ... (longer than the limit), without a cycle.
        home.write("config", "Include c0\n");
        for i in 0..20 {
            home.write(&format!("c{i}"), &format!("Include c{}\n", i + 1));
        }
        let cfg = home.parse();
        assert!(cfg.warnings.iter().any(|w| w.contains("Include depth")));
    }

    #[test]
    fn split_helpers() {
        assert_eq!(split_keyword("Port=22"), ("Port", "22"));
        assert_eq!(split_keyword("Port = 22"), ("Port", "22"));
        assert_eq!(split_keyword("Host\ta b"), ("Host", "a b"));
        assert_eq!(split_keyword("Host"), ("Host", ""));
        assert_eq!(split_args("a \"b c\" d # x"), ["a", "b c", "d"]);
        assert_eq!(split_args("\"\""), [""]);
    }
}
