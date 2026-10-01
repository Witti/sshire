//! Translates key presses into [`Action`]s.
//!
//! The function [`key_to_action`] is *pure*: it depends only on the mode and
//! the key and changes nothing. That makes the key bindings testable and
//! readable in exactly one place.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::app::{Action, Mode};

/// Determines the action for a key in the current mode (`None` = ignore).
///
/// `has_filter` says whether a search filter is active (Esc then clears it).
pub fn key_to_action(mode: Mode, has_filter: bool, key: KeyEvent) -> Option<Action> {
    // Some terminals report release/repeat separately; only "Press" counts.
    if key.kind != KeyEventKind::Press {
        return None;
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    // Ctrl-C quits in every mode. In raw mode it arrives as a normal key
    // (there is no SIGINT then).
    if ctrl && key.code == KeyCode::Char('c') {
        return Some(Action::Quit);
    }
    match mode {
        Mode::Normal => normal_key(has_filter, key.code),
        Mode::Search => search_key(ctrl, key.code),
        // In help, almost any key closes the overlay.
        Mode::Help => Some(Action::CloseHelp),
        // The form and dialogs have their own key logic (text input!): the
        // raw key is passed through and evaluated in the respective state.
        Mode::Form | Mode::TagEdit | Mode::TagFilter | Mode::Secret => Some(Action::Key(key)),
        Mode::Confirm => Some(confirm_key(key.code)),
    }
}

/// Confirmation prompts: only "y" confirms, *any* other key cancels.
fn confirm_key(code: KeyCode) -> Action {
    match code {
        KeyCode::Char('y' | 'Y') => Action::ConfirmYes,
        _ => Action::ConfirmNo,
    }
}

fn normal_key(has_filter: bool, code: KeyCode) -> Option<Action> {
    Some(match code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::Home | KeyCode::Char('g') => Action::First,
        KeyCode::End | KeyCode::Char('G') => Action::Last,
        KeyCode::Enter => Action::Connect,
        KeyCode::Char('f') => Action::ToggleFavorite,
        KeyCode::Char('s') => Action::CycleSort,
        KeyCode::Char('a') => Action::NewHost,
        KeyCode::Char('e') => Action::EditHost,
        KeyCode::Char('t') => Action::EditTags,
        KeyCode::Char('p') => Action::EditPassword,
        KeyCode::Char('d') => Action::DeleteHost,
        KeyCode::Char('x') => Action::ToggleArchive,
        KeyCode::Char('A') => Action::ToggleShowArchived,
        KeyCode::Char('T') => Action::OpenTagFilter,
        KeyCode::Char('/') => Action::OpenSearch,
        KeyCode::Char('?') => Action::OpenHelp,
        // Esc clears a committed filter again.
        KeyCode::Esc if has_filter => Action::CancelSearch,
        _ => return None,
    })
}

fn search_key(ctrl: bool, code: KeyCode) -> Option<Action> {
    Some(match code {
        KeyCode::Esc => Action::CancelSearch,
        KeyCode::Enter => Action::CommitSearch,
        KeyCode::Backspace => Action::SearchBackspace,
        KeyCode::Up => Action::Up,
        KeyCode::Down => Action::Down,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::Char('u') if ctrl => Action::SearchClear,
        KeyCode::Char('p') if ctrl => Action::Up,
        KeyCode::Char('n') if ctrl => Action::Down,
        // Characters pressed with Ctrl/Alt are not text input.
        KeyCode::Char(c) if !ctrl => Action::SearchChar(c),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn normal_mode_bindings() {
        let n = |c| key_to_action(Mode::Normal, false, key(c));
        assert_eq!(n(KeyCode::Char('j')), Some(Action::Down));
        assert_eq!(n(KeyCode::Char('k')), Some(Action::Up));
        assert_eq!(n(KeyCode::Char('G')), Some(Action::Last));
        assert_eq!(n(KeyCode::Char('/')), Some(Action::OpenSearch));
        assert_eq!(n(KeyCode::Enter), Some(Action::Connect));
        assert_eq!(n(KeyCode::Esc), None);
        assert_eq!(
            key_to_action(Mode::Normal, true, key(KeyCode::Esc)),
            Some(Action::CancelSearch)
        );
    }

    #[test]
    fn ctrl_c_quits_everywhere() {
        let ev = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        for mode in [
            Mode::Normal,
            Mode::Search,
            Mode::Help,
            Mode::Form,
            Mode::Confirm,
            Mode::TagEdit,
            Mode::TagFilter,
            Mode::Secret,
        ] {
            assert_eq!(key_to_action(mode, false, ev), Some(Action::Quit));
        }
    }

    #[test]
    fn search_mode_types_text_including_hotkeys() {
        // "q" and "j" are normal letters in search mode.
        let s = |c| key_to_action(Mode::Search, false, key(c));
        assert_eq!(s(KeyCode::Char('q')), Some(Action::SearchChar('q')));
        assert_eq!(s(KeyCode::Char('#')), Some(Action::SearchChar('#')));
        assert_eq!(s(KeyCode::Esc), Some(Action::CancelSearch));
        assert_eq!(s(KeyCode::Enter), Some(Action::CommitSearch));
    }

    #[test]
    fn help_closes_on_any_key() {
        assert_eq!(
            key_to_action(Mode::Help, false, key(KeyCode::Char('x'))),
            Some(Action::CloseHelp)
        );
    }

    #[test]
    fn management_bindings_in_normal_mode() {
        let n = |c| key_to_action(Mode::Normal, false, key(KeyCode::Char(c)));
        assert_eq!(n('a'), Some(Action::NewHost));
        assert_eq!(n('e'), Some(Action::EditHost));
        assert_eq!(n('t'), Some(Action::EditTags));
        assert_eq!(n('p'), Some(Action::EditPassword));
        assert_eq!(n('d'), Some(Action::DeleteHost));
        assert_eq!(n('x'), Some(Action::ToggleArchive));
        assert_eq!(n('A'), Some(Action::ToggleShowArchived));
        assert_eq!(n('T'), Some(Action::OpenTagFilter));
    }

    #[test]
    fn confirm_mode_only_yes_keys_confirm() {
        let c = |code| key_to_action(Mode::Confirm, false, key(code));
        for ch in ['y', 'Y'] {
            assert_eq!(c(KeyCode::Char(ch)), Some(Action::ConfirmYes));
        }
        assert_eq!(c(KeyCode::Char('j')), Some(Action::ConfirmNo));
        assert_eq!(c(KeyCode::Char('n')), Some(Action::ConfirmNo));
        assert_eq!(c(KeyCode::Enter), Some(Action::ConfirmNo));
        assert_eq!(c(KeyCode::Esc), Some(Action::ConfirmNo));
    }

    #[test]
    fn form_and_dialog_modes_pass_raw_keys_through() {
        // Hotkeys like "q" or "d" must remain normal letters in the form.
        for mode in [Mode::Form, Mode::TagEdit, Mode::TagFilter, Mode::Secret] {
            let ev = key(KeyCode::Char('q'));
            assert_eq!(key_to_action(mode, false, ev), Some(Action::Key(ev)));
        }
    }

    #[test]
    fn release_events_are_ignored() {
        let mut ev = key(KeyCode::Char('j'));
        ev.kind = KeyEventKind::Release;
        assert_eq!(key_to_action(Mode::Normal, false, ev), None);
    }
}
