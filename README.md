# WSL SSH Askpass

A Windows SSH askpass utility with Windows Hello support, designed for use with WSL.

## Features

- GUI password prompt for SSH passphrases
- Windows Hello biometric authentication support
- Credential caching using Windows Credential Manager
- Host key verification dialogs (yes/no prompts)
- 5-minute Windows Hello session cache

## Building

### Prerequisites

1. Install Rust: https://rustup.rs/
2. Install cargo-xwin for cross-compilation from Linux:
   ```bash
   cargo install cargo-xwin
   ```
3. Add the Windows target:
   ```bash
   rustup target add x86_64-pc-windows-msvc
   ```

### Build Commands

**Debug build:**
```bash
cargo xwin build --target x86_64-pc-windows-msvc
```

**Release build (optimized):**
```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

The output binary will be at:
- Debug: `target/x86_64-pc-windows-msvc/debug/wsl-ssh-askpass.exe`
- Release: `target/x86_64-pc-windows-msvc/release/wsl-ssh-askpass.exe`

## Usage

### With WSL SSH

Set the `SSH_ASKPASS` environment variable in your WSL shell:

```bash
export SSH_ASKPASS="/mnt/c/path/to/wsl-ssh-askpass.exe"
export SSH_ASKPASS_REQUIRE=force
```

Add these to your `~/.bashrc` or `~/.zshrc` for persistence.

### How it works

1. When SSH needs a passphrase, it calls this utility with the prompt as an argument
2. The utility checks for a cached passphrase in Windows Credential Manager
3. If cached and Windows Hello session is valid, returns the passphrase immediately
4. If cached but Hello session expired, prompts for Windows Hello verification
5. If not cached, shows a credential dialog, caches the passphrase, and returns it

### Credential Storage

- Passphrases are stored in Windows Credential Manager with the prefix `ssh-askpass:`
- Windows Hello timestamps use `ssh-askpass:hello-timestamp`
- Passphrases persist until manually deleted
- Windows Hello verification is cached for 5 minutes

## License

MIT
