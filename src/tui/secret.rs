//! State of the password dialog (key `p`) and the master password prompt.
//!
//! The dialog is a small state machine: depending on the [`Step`] it asks for
//! something different. This module knows neither the database nor the
//! `SecretStore`; it only stores inputs and intermediate state. The
//! transitions (what happens after "Enter") are decided by `app.rs`, which has
//! access to the store and the vault.
//!
//! All secrets live in [`SecretString`] or [`MaskedInput`]
//! (both are overwritten when dropped). If the user cancels with Esc or the
//! dialog is closed, the inputs disappear immediately as a result.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use super::input::MaskedInput;
use crate::secrets::SecretString;
use crate::store::Host;

/// Which step the dialog is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Enter a new host password (empty = remove, if one exists).
    EnterPassword,
    /// Repeat the host password to double-check it.
    RepeatPassword,
    /// Confirmation prompt "Remove password?".
    ConfirmRemove,
    /// Enter the master password of the encrypted vault.
    Unlock,
    /// Set a new master password.
    NewMaster,
    /// Repeat the new master password.
    RepeatMaster,
}

/// Why the dialog was opened.
pub enum Intent {
    /// Set, change or remove the host password (`p`).
    SetPassword,
    /// Only unlock, then connect (Enter on a host with a password).
    Connect(Box<Host>),
}

/// What a key press did in the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogEvent {
    /// Only the input state changed (or nothing).
    None,
    /// The user cancelled.
    Cancel,
    /// The user confirmed the step (Enter or "yes").
    Submit,
}

/// The dialog together with its intermediate state.
pub struct SecretDialog {
    pub host_id: i64,
    pub alias: String,
    /// Does the host already have a password? (controls "empty = remove")
    pub has_password: bool,
    pub step: Step,
    /// The masked input field of the current step.
    pub input: MaskedInput,
    /// Error message for the last attempt.
    pub error: Option<String>,
    pub intent: Intent,
    /// First input (password or master) while the repetition is in progress.
    first: Option<SecretString>,
    /// Fully confirmed host password that is still waiting for the unlock.
    pending: Option<SecretString>,
}

impl SecretDialog {
    /// Dialog for setting/changing/removing the password of `host`.
    pub fn for_password(host: &Host) -> Self {
        Self::new(host, Step::EnterPassword, Intent::SetPassword)
    }

    /// Dialog that only unlocks and then connects to `host`.
    pub fn for_connect(host: Host) -> Self {
        let mut dialog = Self::new(&host, Step::Unlock, Intent::Connect(Box::new(host.clone())));
        dialog.has_password = true;
        dialog
    }

    fn new(host: &Host, step: Step, intent: Intent) -> Self {
        Self {
            host_id: host.id,
            alias: host.alias.clone(),
            has_password: host.has_password,
            step,
            input: MaskedInput::new(),
            error: None,
            intent,
            first: None,
            pending: None,
        }
    }

    /// Evaluates a key press. The caller performs the actual transitions based on the result.
    pub fn handle_key(&mut self, key: KeyEvent) -> DialogEvent {
        if key.kind != KeyEventKind::Press {
            return DialogEvent::None;
        }
        if self.step == Step::ConfirmRemove {
            return match key.code {
                KeyCode::Char('y' | 'Y') => DialogEvent::Submit,
                // As with all confirmation prompts: any other key cancels.
                _ => DialogEvent::Cancel,
            };
        }
        match key.code {
            KeyCode::Esc => DialogEvent::Cancel,
            KeyCode::Enter => DialogEvent::Submit,
            _ => {
                if self.input.handle_key(key) {
                    // New input makes the old error message obsolete.
                    self.error = None;
                }
                DialogEvent::None
            }
        }
    }

    /// Switches the step and clears the input field.
    pub fn goto(&mut self, step: Step) {
        self.step = step;
        self.input.clear();
    }

    /// Shows an error message and clears the input field.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.error = Some(message.into());
        self.input.clear();
    }

    /// Takes out the current input (the field is empty afterwards).
    pub fn take_input(&mut self) -> SecretString {
        self.input.take()
    }

    /// Remembers the first input for the repeat step.
    pub fn remember_first(&mut self, secret: SecretString) {
        self.first = Some(secret);
    }

    /// Fetches the remembered first input (and forgets it).
    pub fn take_first(&mut self) -> Option<SecretString> {
        self.first.take()
    }

    /// Remembers the confirmed host password until the unlock.
    pub fn set_pending(&mut self, secret: SecretString) {
        self.pending = Some(secret);
    }

    /// Fetches the confirmed host password (and forgets it).
    pub fn take_pending(&mut self) -> Option<SecretString> {
        self.pending.take()
    }

    /// Title of the popup.
    pub fn title(&self) -> String {
        match self.step {
            Step::EnterPassword | Step::RepeatPassword | Step::ConfirmRemove => {
                format!("Password for \"{}\"", self.alias)
            }
            Step::Unlock => "Unlock password vault".to_owned(),
            Step::NewMaster | Step::RepeatMaster => "Set master password".to_owned(),
        }
    }

    /// Label in front of the input field.
    pub fn prompt(&self) -> &'static str {
        match self.step {
            Step::EnterPassword => "Password",
            Step::RepeatPassword => "Repeat",
            Step::Unlock => "Master password",
            Step::NewMaster => "New master password",
            Step::RepeatMaster => "Repeat",
            Step::ConfirmRemove => "",
        }
    }

    /// Explanatory text below the input field.
    pub fn explanation(&self) -> Option<&'static str> {
        match self.step {
            Step::EnterPassword if self.has_password => {
                Some("Leave empty and press ⏎ to remove the password.")
            }
            Step::Unlock => Some("Unlocks the encrypted password vault for this session."),
            Step::NewMaster => Some(
                "Protects all passwords (at least 8 characters). There is no recovery, so don't forget it!",
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyModifiers;

    use super::*;
    use crate::store::{AuthMethod, HostSource};

    fn host() -> Host {
        Host {
            id: 3,
            alias: "web".into(),
            hostname: None,
            user: None,
            port: None,
            identity_file: None,
            proxy_jump: None,
            extra_args: None,
            icon: None,
            color: None,
            notes: None,
            source: HostSource::Manual,
            favorite: false,
            archived: false,
            auth_method: AuthMethod::Agent,
            has_password: false,
            created_at: 0,
            updated_at: 0,
            tags: Vec::new(),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn typing_enter_and_escape() {
        let mut dialog = SecretDialog::for_password(&host());
        assert_eq!(
            dialog.handle_key(key(KeyCode::Char('a'))),
            DialogEvent::None
        );
        assert_eq!(
            dialog.handle_key(key(KeyCode::Char('b'))),
            DialogEvent::None
        );
        assert_eq!(dialog.take_input().expose(), "ab");
        assert_eq!(dialog.handle_key(key(KeyCode::Enter)), DialogEvent::Submit);
        assert_eq!(dialog.handle_key(key(KeyCode::Esc)), DialogEvent::Cancel);
    }

    #[test]
    fn typing_clears_the_error() {
        let mut dialog = SecretDialog::for_password(&host());
        dialog.fail("broken");
        assert!(dialog.error.is_some());
        dialog.handle_key(key(KeyCode::Char('x')));
        assert!(dialog.error.is_none());
    }

    #[test]
    fn confirm_remove_only_accepts_yes_keys() {
        let mut dialog = SecretDialog::for_password(&host());
        dialog.goto(Step::ConfirmRemove);
        assert_eq!(
            dialog.handle_key(key(KeyCode::Char('n'))),
            DialogEvent::Cancel
        );
        assert_eq!(dialog.handle_key(key(KeyCode::Enter)), DialogEvent::Cancel);
        assert_eq!(
            dialog.handle_key(key(KeyCode::Char('j'))),
            DialogEvent::Cancel
        );
        assert_eq!(
            dialog.handle_key(key(KeyCode::Char('y'))),
            DialogEvent::Submit
        );
        assert_eq!(
            dialog.handle_key(key(KeyCode::Char('Y'))),
            DialogEvent::Submit
        );
    }

    #[test]
    fn first_and_pending_are_taken_once() {
        let mut dialog = SecretDialog::for_password(&host());
        dialog.remember_first(SecretString::new("one".into()));
        assert_eq!(dialog.take_first().unwrap().expose(), "one");
        assert!(dialog.take_first().is_none());
        dialog.set_pending(SecretString::new("two".into()));
        assert_eq!(dialog.take_pending().unwrap().expose(), "two");
        assert!(dialog.take_pending().is_none());
    }
}
