use std::env;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use windows::{
    core::{Error, Result, HSTRING, PCWSTR, PWSTR},
    Foundation::IAsyncOperation,
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Win32::Foundation::{LocalFree, BOOL, HLOCAL, HWND},
    Win32::Graphics::Gdi::HBITMAP,
    Win32::Security::Credentials::{
        CredFree, CredPackAuthenticationBufferW, CredReadW, CredUIPromptForWindowsCredentialsW,
        CredUnPackAuthenticationBufferW, CredWriteW, CREDENTIALW, CREDUIWIN_CHECKBOX,
        CREDUIWIN_GENERIC, CREDUIWIN_IN_CRED_ONLY, CREDUI_INFOW, CRED_FLAGS,
        CRED_PACK_GENERIC_CREDENTIALS, CRED_PERSIST_LOCAL_MACHINE, CRED_PERSIST_SESSION,
        CRED_TYPE_GENERIC,
    },
    Win32::System::WinRT::IUserConsentVerifierInterop,
    Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, MessageBoxW, SetForegroundWindow, IDYES, MB_DEFBUTTON2,
        MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
    },
};

// Constants
const CACHE_PIN_TTL_SECS: u64 = 60 * 5; // 5 minutes
const CRED_PREFIX: &str = "wsl-ssh-askpass";

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Extract key name from prompt like "Enter passphrase for key '/path/to/key':"
fn extract_key_name(prompt: &str) -> String {
    if let Some(start) = prompt.find('\'') {
        if let Some(end) = prompt[start + 1..].find('\'') {
            let key_path = &prompt[start + 1..start + 1 + end];
            // Return just the filename
            return key_path
                .rsplit('/')
                .next()
                .or_else(|| key_path.rsplit('\\').next())
                .unwrap_or(key_path)
                .to_string();
        }
    }
    "default".to_string()
}

fn cred_name(key: &str) -> String {
    format!("{}:{}", CRED_PREFIX, key)
}

fn hello_cred_name(key: &str) -> String {
    format!("{}:{}:{}", CRED_PREFIX, key, "temp")
}

fn main() {
    let prompt = env::args()
        .nth(1)
        .unwrap_or_else(|| "Enter SSH passphrase:".into());

    let prompt_lower = prompt.to_lowercase();

    if prompt_lower.contains("yes/no") || prompt_lower.contains("fingerprint") {
        // Host key verification
        let answer = prompt_yes_no(&prompt);
        print!("{}", answer);
    } else {
        // Passphrase request
        if let Some(pass) = handle_passphrase(&prompt) {
            print!("{}", pass);
        } else {
            std::process::exit(1);
        }
    }
    io::stdout().flush().ok();
}

fn handle_passphrase(prompt: &str) -> Option<String> {
    let key_name = extract_key_name(prompt);

    // Try cached passphrase with Windows Hello
    if let Some(pass) = get_cached_passphrase(&key_name) {
        if is_hello_valid(&key_name) || verify_with_hello(&key_name) {
            update_hello_timestamp(&key_name);
            return Some(pass);
        }
    }

    // Prompt for new passphrase
    let (pass, save) = prompt_for_password(prompt, &key_name).ok()?;
    if save {
        let _ = cache_passphrase(&key_name, &pass);
    }
    update_hello_timestamp(&key_name);
    Some(pass)
}

fn get_foreground_hwnd() -> HWND {
    unsafe { GetForegroundWindow() }
}

fn prompt_yes_no(prompt: &str) -> &'static str {
    let title = to_wide("SSH Host Verification");
    let content = to_wide(prompt);
    unsafe {
        let parent = get_foreground_hwnd();
        let result = MessageBoxW(
            parent,
            PCWSTR(content.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND,
        );
        if result == IDYES {
            "yes"
        } else {
            "no"
        }
    }
}

fn prompt_for_password(prompt: &str, key_name: &str) -> Result<(String, bool)> {
    let message = to_wide(prompt);
    let caption = to_wide("SSH Passphrase");
    let username = to_wide(key_name);
    let empty_pass = to_wide("");

    unsafe {
        let parent = get_foreground_hwnd();
        // Try to bring our dialog to the foreground
        if !parent.is_invalid() {
            let _ = SetForegroundWindow(parent);
        }

        let ui_info = CREDUI_INFOW {
            cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: parent,
            pszMessageText: PCWSTR(message.as_ptr()),
            pszCaptionText: PCWSTR(caption.as_ptr()),
            hbmBanner: HBITMAP::default(),
        };

        // Pack the key name as username to pre-populate the field
        let mut in_buf_size: u32 = 0;
        let _ = CredPackAuthenticationBufferW(
            CRED_PACK_GENERIC_CREDENTIALS,
            PCWSTR(username.as_ptr()),
            PCWSTR(empty_pass.as_ptr()),
            None,
            &mut in_buf_size,
        );

        let mut in_buf = vec![0u8; in_buf_size as usize];
        CredPackAuthenticationBufferW(
            CRED_PACK_GENERIC_CREDENTIALS,
            PCWSTR(username.as_ptr()),
            PCWSTR(empty_pass.as_ptr()),
            Some(in_buf.as_mut_ptr() as *mut _),
            &mut in_buf_size,
        )?;

        let mut auth_package: u32 = 0;
        let mut out_buf: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut out_buf_size: u32 = 0;
        let mut save_checked = BOOL(0);

        // CREDUIWIN_IN_CRED_ONLY makes the username field read-only
        let result = CredUIPromptForWindowsCredentialsW(
            Some(&ui_info),
            0,
            &mut auth_package,
            Some(in_buf.as_ptr() as *const _),
            in_buf_size,
            &mut out_buf,
            &mut out_buf_size,
            Some(&mut save_checked),
            CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX | CREDUIWIN_IN_CRED_ONLY,
        );

        if result != 0 {
            return Err(Error::from_win32());
        }

        let mut username = vec![0u16; 256];
        let mut username_len: u32 = 256;
        let mut password = vec![0u16; 256];
        let mut password_len: u32 = 256;

        let unpack = CredUnPackAuthenticationBufferW(
            CRED_PACK_GENERIC_CREDENTIALS,
            out_buf,
            out_buf_size,
            PWSTR(username.as_mut_ptr()),
            &mut username_len,
            PWSTR::null(),
            None,
            PWSTR(password.as_mut_ptr()),
            &mut password_len,
        );

        let _ = LocalFree(HLOCAL(out_buf));

        if unpack.is_err() {
            return Err(Error::from_win32());
        }

        let pass_len = password_len.saturating_sub(1) as usize;
        let pass = String::from_utf16_lossy(&password[..pass_len]);
        Ok((pass, save_checked.as_bool()))
    }
}

fn get_cached_passphrase(key: &str) -> Option<String> {
    let name = to_wide(&cred_name(key));
    unsafe {
        let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();
        if CredReadW(PCWSTR(name.as_ptr()), CRED_TYPE_GENERIC, 0, &mut cred_ptr).is_ok() {
            let cred = &*cred_ptr;
            let blob =
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize);
            let pass = String::from_utf8_lossy(blob).to_string();
            CredFree(cred_ptr as *mut _);
            return Some(pass);
        }
    }
    None
}

fn cache_passphrase(key: &str, passphrase: &str) -> Result<()> {
    let name = to_wide(&cred_name(key));
    let username = to_wide(CRED_PREFIX);
    let blob = passphrase.as_bytes();
    unsafe {
        let cred = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(name.as_ptr() as *mut _),
            Comment: PWSTR::null(),
            LastWritten: std::mem::zeroed(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr() as *mut _,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR(username.as_ptr() as *mut _),
        };
        CredWriteW(&cred, 0)?;
    }
    Ok(())
}

fn is_hello_valid(key: &str) -> bool {
    let name = to_wide(&hello_cred_name(key));
    unsafe {
        let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();
        if CredReadW(PCWSTR(name.as_ptr()), CRED_TYPE_GENERIC, 0, &mut cred_ptr).is_ok() {
            let cred = &*cred_ptr;
            let blob =
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize);
            let ts_str = String::from_utf8_lossy(blob);
            if let Ok(stored) = ts_str.parse::<u64>() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                CredFree(cred_ptr as *mut _);
                return now - stored < CACHE_PIN_TTL_SECS;
            }
            CredFree(cred_ptr as *mut _);
        }
    }
    false
}

fn update_hello_timestamp(key: &str) {
    let name = to_wide(&hello_cred_name(key));
    let username = to_wide(CRED_PREFIX);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let blob = ts.as_bytes();
    unsafe {
        let cred = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(name.as_ptr() as *mut _),
            Comment: PWSTR::null(),
            LastWritten: std::mem::zeroed(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr() as *mut _,
            Persist: CRED_PERSIST_SESSION,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR(username.as_ptr() as *mut _),
        };
        let _ = CredWriteW(&cred, 0);
    }
}

fn verify_with_hello(key: &str) -> bool {
    unsafe { verify_with_hello_inner(key).unwrap_or(false) }
}

unsafe fn verify_with_hello_inner(key: &str) -> Result<bool> {
    let availability = UserConsentVerifier::CheckAvailabilityAsync()?.get()?;
    if availability != UserConsentVerifierAvailability::Available {
        return Ok(false);
    }

    let hwnd = GetForegroundWindow();
    let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    let message = HSTRING::from(format!("Unlock SSH key: {}", key));
    let result: UserConsentVerificationResult = interop
        .RequestVerificationForWindowAsync::<_, IAsyncOperation<UserConsentVerificationResult>>(
            hwnd, &message,
        )?
        .get()?;

    Ok(result == UserConsentVerificationResult::Verified)
}
