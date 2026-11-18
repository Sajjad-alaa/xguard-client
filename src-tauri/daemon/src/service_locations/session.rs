//! Whether a user is signed in, for pre-logon service locations.
//!
//! When it cannot be told, the answer is "nobody", so pre-logon tunnels stay up (the safe
//! direction for a tunnel meant to let people sign in).

/// Linux: systemd-logind's session files in `/run/systemd/sessions`. A session of class `user`
/// in state `active` or `online` counts (graphical, console or remote).
#[cfg(target_os = "linux")]
#[must_use]
pub fn user_signed_in() -> bool {
    let Ok(entries) = std::fs::read_dir("/run/systemd/sessions") else {
        return false;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| {
            // Session files are small; skip anything unusual.
            let metadata = entry.metadata().ok()?;
            (metadata.len() <= 64 * 1024).then(|| std::fs::read_to_string(entry.path()).ok())?
        })
        .any(|content| logind_session_is_user(&content))
}

/// Parses one logind session file.
#[must_use]
pub fn logind_session_is_user(content: &str) -> bool {
    let mut class = None;
    let mut state = None;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("CLASS=") {
            class = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("STATE=") {
            state = Some(value.trim());
        }
    }
    class == Some("user") && matches!(state, Some("active" | "online"))
}

/// Windows: a user is signed in to the console session.
#[cfg(windows)]
#[must_use]
pub fn user_signed_in() -> bool {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
        WTS_CURRENT_SERVER_HANDLE,
    };

    // SAFETY: plain Win32 calls; the buffer is freed with WTSFreeMemory and read only within
    // the returned length.
    unsafe {
        let session = WTSGetActiveConsoleSessionId();
        if session == u32::MAX {
            return false;
        }
        let mut buffer: *mut u16 = std::ptr::null_mut();
        let mut bytes: u32 = 0;
        if WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            WTSUserName,
            &mut buffer,
            &mut bytes,
        ) == 0
            || buffer.is_null()
        {
            return false;
        }
        let units = (bytes as usize / 2).saturating_sub(1);
        let name = std::slice::from_raw_parts(buffer, units);
        let signed_in = name.iter().any(|unit| *unit != 0);
        WTSFreeMemory(buffer.cast());
        signed_in
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
#[must_use]
pub fn user_signed_in() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_logind_sessions() {
        let graphical = "# This is private data. Do not parse.\nUID=1000\nUSER=alice\nACTIVE=1\n\
            IS_DISPLAY=1\nSTATE=active\nREMOTE=0\nTYPE=wayland\nCLASS=user\n";
        assert!(logind_session_is_user(graphical));
        assert!(logind_session_is_user(
            "CLASS=user\nSTATE=online\nTYPE=tty\n"
        ));
        // The display manager's greeter is not a signed-in user.
        assert!(!logind_session_is_user("CLASS=greeter\nSTATE=active\n"));
        assert!(!logind_session_is_user("CLASS=user\nSTATE=closing\n"));
        assert!(!logind_session_is_user("CLASS=background\nSTATE=active\n"));
        assert!(!logind_session_is_user(""));
    }
}
