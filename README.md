# sshire 🏡

A TUI SSH launcher in Rust as an alternative to `sshs` — with independent host management, icons, tags, connection log, and secure password storage. The name is a play on the Shire, home of the Hobbits in Tolkien's works — a cozy home for your SSH hosts.

## Features

- **TUI** (Terminal User Interface): Interactive, fuzzy-searchable host list with detail panel and connection history
- **Host Management**: Create/edit hosts manually or auto-import from `~/.ssh/config`
- **Icons & Tags**: Each host can have a symbol (emoji/Unicode) and any number of tags
- **Secure Passwords**: macOS Keychain or Linux encryption (XChaCha20-Poly1305 + Argon2id) with master password; 🔑 marking in the host list
- **Connection Log**: Success/failure status and duration of each SSH connection
- **CLI Mode**: List hosts, connect, manage passwords — all without the TUI
- **Export**: Export hosts as JSON (without passwords)
- **Read-only**: `~/.ssh/config` is imported but never modified

## Screenshot

<!-- Screenshot coming -->

## Installation

> Replace `<owner>` below with the GitHub user or organization that hosts sshire.

### Homebrew (macOS and Linux) – recommended

```sh
brew install <owner>/tap/sshire
```

This installs the pre-built binary from the latest GitHub release – no Rust
toolchain needed, and no Gatekeeper prompt on macOS. Update with
`brew upgrade sshire`, remove with `brew uninstall sshire`.

### Pre-built binary

Download the archive for your platform from the GitHub releases page, extract it
and place `sshire` in your `PATH`:

```sh
tar -xzf sshire-<version>-macos-universal.tar.gz
sudo mv sshire-<version>-macos-universal/sshire /usr/local/bin/
```

On macOS, the binary is not notarized. If you downloaded the archive via a browser,
Gatekeeper will block it; remove the quarantine flag once with:

```sh
xattr -d com.apple.quarantine /usr/local/bin/sshire
```

The Linux archives contain statically linked binaries (musl) and run without
additional dependencies on virtually any distribution.

### From source

Requires Rust (macOS: `brew install rustup` then `rustup default stable`;
Linux: see [rustup.rs](https://rustup.rs/)).

```sh
git clone https://github.com/<owner>/sshire.git
cd sshire
cargo install --path .
```

### Requirements

- **OpenSSH ≥ 8.4** for the password feature (macOS and current Linux
  distributions ship a newer version).

## Usage

### Start the TUI

```sh
sshire
```

Without additional arguments, the interactive terminal interface opens.

### Keybindings

| Key | Function |
|-------|----------|
| **Navigation** | |
| ↑ ↓ / `j` `k` | Move selection |
| `PgUp` / `PgDn` | Page up/down |
| `g` / `G` / `Home` / `End` | Jump to start/end |
| **Actions** | |
| `Enter` | Connect to selected host |
| `/` | Search (fuzzy; `#tag` filters by tag) |
| `Esc` | Clear/close search |
| `f` | Toggle favorite |
| `s` | Sort: Name → last success → frequent |
| **Management** | |
| `a` | Create new manual host |
| `e` | Edit host (ssh_config: icon/tags/notes only) |
| `t` | Edit host tags (comma-separated) |
| `T` | Filter by tag (list all tags) |
| `p` | Set/change/remove password |
| `d` | Delete manual host (with confirmation) |
| `x` | Archive/restore host |
| `A` | Toggle archived hosts visibility |
| **Help & Exit** | |
| `?` | Show this help |
| `q` / `Ctrl-C` | Exit TUI |
| **In forms** | Tab/↑↓ = move field · Ctrl-S = save · Esc = cancel |

### CLI commands

```sh
# List all hosts (table with icon, tags, last success time)
sshire list
sshire list --tag prod        # Only hosts with tag 'prod'

# Connect to a host
sshire connect web            # Connect to host 'web'

# Show connection log
sshire log                     # All entries (default: last 20)
sshire log web --limit 5      # Only host 'web', 5 entries

# Create new host
sshire add                     # Interactive
sshire add --alias web --host web.example.com --user admin --port 2222

# Import hosts
sshire import                  # Read ~/.ssh/config and sync database

# Manage passwords
sshire passwd web             # Set/change password for 'web'
sshire passwd web --delete    # Remove password
sshire passwd --master        # Change master password (Linux)

# Export hosts
sshire export                 # JSON (without passwords; --json is equivalent)
sshire export --json > hosts.json
sshire export --json --include-archived  # Including archived hosts
```

## Data storage

sshire stores its data in the platform-standard directory:

- **macOS**: `~/Library/Application Support/sshire/`
- **Linux**: `~/.local/share/sshire/` and `~/.config/sshire/` (XDG standard)

The database file is called `sshire.db` (SQLite). The `~/.ssh/config` is read on startup and via `sshire import`, but **never written**.

## Passwords & Security

### macOS: Keychain
On macOS, passwords are stored directly in the system Keychain (service `sshire`). No password exists in the SQLite file.

### Linux: Encrypted storage
- **Cipher**: XChaCha20-Poly1305 (AuthEncrypted)
- **Key derivation**: Argon2id (64 MiB, 3 iterations) with random salt
- **Host binding**: Each ciphertext is bound to its host via AAD — swapped entries cannot be decrypted
- **Master password**: When setting a password for the first time, you are prompted for a master password (minimum 8 characters)
- **Memory**: Passwords flow through the program as `SecretString` (with automatic overwriting on drop)

### Password delivery to SSH
The password is **not** transmitted via arguments, environment variables, or files:

1. sshire retrieves the password from storage (Keychain or decrypted).
2. A one-time Unix socket is created in a 0700 directory.
3. `ssh` is started with `SSH_ASKPASS=<path/to/sshire>`, `SSH_ASKPASS_REQUIRE=force`, plus socket path and random token (`SSHIRE_ASKPASS_SOCK`/`_TOKEN`).
4. When ssh asks for the password, it calls `sshire "<question>"`. This invocation authenticates at the socket with the token.
5. The parent process verifies the token (constant-time) and sends the password, which goes to stdout for ssh.
6. The password is delivered only **once**; then the socket closes and the directory is deleted.
7. Other ssh prompts (host key confirmation, key passphrase) remain interactive in the terminal.

### Honest limitations
- Malware running as the same user can debug SSH processes or read the token — before the password is delivered.
- A weak master password (Linux) can be guessed despite Argon2id — only 8 characters are enforced.
- The decrypted key remains in memory until program exit.
- No recovery method for lost master passwords.

## Configuration

The `config.toml` file in the config directory (see above) controls behavior:

```toml
# Theme
theme = "mocha"  # Options: mocha, latte, tokyo-night, gruvbox

# Default sort on startup
default_sort = "name"  # Options: name, recent, frequent

# Show archived hosts by default?
show_archived = false

# Icon fallback when a host has no icon
icon_fallback = "•"

# SSH command and extra arguments
[ssh]
program = "ssh"
extra_args = []  # e.g. ["-v"] for verbose output
```

Example directories:
- **macOS**: `~/Library/Application Support/sshire/config.toml` (`sshire config --path` shows the exact path)
- **Linux**: `~/.config/sshire/config.toml`

**Commands:**
```sh
sshire config --path       # Print path to config.toml
sshire config --example    # Show annotated example configuration
sshire config --example > "$(sshire config --path)"   # Create as a starting point
```

## Learning Rust with this code

The sshire source is well-suited for learning Rust concepts. Code comments are in English and explain Rust ideas on first use. Here is a recommended reading order:

1. **`src/cli.rs`** – Derive macros, `enum`, `match`, `clap` argument parsing
2. **`src/paths.rs`** – `Result<T, E>`, the `?` operator, `thiserror`, error handling
3. **`src/store/mod.rs`** – Traits (`impl`), SQL abstraction, transactions, RAII cleanup
4. **`src/sshconfig/parser.rs`** – String processing, iterators, recursion, pattern matching
5. **`src/connect/mod.rs`** – Process management, exit codes, RAII guards for cleanup
6. **`src/secrets/mod.rs`** – Trait objects (`dyn`), conditional compilation (`#[cfg]`), cryptography, `zeroize`
7. **`src/connect/askpass.rs`** – Threads, atomics, Unix sockets, constant-time comparison, `move` closures
8. **`src/tui/app.rs` and `src/tui/ui.rs`** – Elm architecture, lifetimes with `&'a`, state-driven rendering
9. **`src/config.rs`** – `serde` derive, manual `Default`, enums as strings in TOML

## Development

The project follows strict quality gates. Before every commit/PR, these commands must pass:

```sh
# Check code format (no auto-format)
cargo fmt --check

# Linter with all warnings as errors
cargo clippy --all-targets -- -D warnings

# Unit tests
cargo test
```

No `unwrap()` or `expect()` outside tests (except with a comment explaining why it is safe).

## Releasing (maintainers)

### Build release archives locally

```sh
./scripts/release.sh            # macOS universal + Linux x86_64/aarch64 (requires Docker)
./scripts/release.sh --no-linux # macOS only
```

Results are in `dist/` including `SHA256SUMS`.

### Release via GitHub

Pushing a version tag triggers the workflow [`.github/workflows/release.yml`](.github/workflows/release.yml):
it checks fmt/clippy/tests on macOS and Linux, builds all three archives, creates
a GitHub release with `SHA256SUMS` and auto-generated release notes, and updates
the Homebrew tap.

```sh
# 1. Bump version in Cargo.toml (must match the tag), commit
# 2. Create and push the tag
git tag v0.2.0
git push origin v0.2.0
```

Tags with a hyphen (e.g. `v0.2.0-rc.1`) are published as pre-releases and do not
update the Homebrew tap.

### Homebrew tap setup (one time)

`brew install <owner>/tap/sshire` looks for the repository
`github.com/<owner>/homebrew-tap` and the file `Formula/sshire.rb` in it.
The release workflow keeps that file up to date; it only needs to be set up once:

1. Create a **public** repository named `homebrew-tap` under the same owner as
   sshire (an empty repository with a README is fine).
2. Create a fine-grained personal access token (GitHub → Settings → Developer
   settings → Fine-grained tokens) with access to **only** the `homebrew-tap`
   repository and the permission **Contents: Read and write**.
3. Add it to the sshire repository as an Actions secret named
   `HOMEBREW_TAP_TOKEN` (Settings → Secrets and variables → Actions).
4. Push a version tag. After the release, the `Update Homebrew tap` job commits
   the generated formula to the tap.

Without the secret the job is skipped and the release still succeeds. To create
or fix the formula by hand, generate it from a release's checksums:

```sh
scripts/homebrew-formula.sh 0.2.0 dist/SHA256SUMS <owner>/sshire > Formula/sshire.rb
```

Getting into the official `homebrew/core` (so that a plain `brew install sshire`
works) requires a project with an established user base and a source build;
the own tap is the usual way to start.

## License

sshire is available under your choice of either of the following licenses:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in sshire by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
