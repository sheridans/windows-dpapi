//! Windows Data Protection API (DPAPI) wrapper for Rust
//!
//! This library provides a safe wrapper around Windows' built-in encryption system (DPAPI).
//! It allows you to encrypt and decrypt data that is tied to either the current user
//! or the local machine.
//!
//! # Security Considerations
//!
//! - Data encrypted with `Scope::User` can only be decrypted by the same user on the same machine
//! - Data encrypted with `Scope::Machine` can be decrypted by any user on the same machine
//! - Encrypted data cannot be decrypted on a different machine
//! - The encryption is tied to the Windows user/machine credentials
//!
//! # Examples
//!
//! ```rust
//! use windows_dpapi::{encrypt_data, decrypt_data, Scope};
//!
//! fn main() -> anyhow::Result<()> {
//!     // Encrypt data for current user only
//!     let secret = b"my secret data";
//!     let encrypted = encrypt_data(secret, Scope::User, None)?;
//!
//!     // Decrypt the data
//!     let decrypted = decrypt_data(&encrypted, Scope::User, None)?;
//!     assert_eq!(secret, decrypted.as_slice());
//!     Ok(())
//! }
//! ```
//!
//! # Common Use Cases
//!
//! - Storing application secrets
//! - Securing user credentials
//! - Protecting sensitive configuration data
//!
//! # Limitations
//!
//! - Windows-only (this crate will not compile on other platforms)
//! - Data cannot be decrypted on a different machine
//! - Machine scope is less secure than user scope

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use std::{ptr, slice};
#[cfg(windows)]
use winapi::shared::minwindef::DWORD;
#[cfg(windows)]
use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData};
#[cfg(windows)]
use winapi::um::wincrypt::DATA_BLOB;

/// Defines the encryption scope: user or machine
#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
pub enum Scope {
    /// Tied to current user account. Data can only be decrypted by the same user
    /// on the same machine. This is the most secure option for user-specific data.
    ///
    /// # Security
    ///
    /// - Data is encrypted using the current user's credentials
    /// - Only the same user on the same machine can decrypt the data
    /// - If the user's password changes, the data can still be decrypted
    /// - If the user is deleted, the data cannot be decrypted
    /// - Note: The decryption will only succeed if the data was encrypted with
    ///   Scope::User by the same user. The scope flag is used during encryption
    ///   to determine which key to use.
    User,

    /// Tied to local machine. Data can be decrypted by any user on the same machine.
    ///
    /// # Security
    ///
    /// - Data is encrypted using the machine's credentials
    /// - Any user on the same machine can decrypt the data
    /// - Useful for shared secrets that need to be accessible to all users
    /// - Less secure than user scope as it's accessible to all local users
    /// - Note: The decryption will only succeed if the data was encrypted with
    ///   Scope::Machine. The scope flag is used during encryption to determine
    ///   which key to use.
    Machine,
}

#[cfg(windows)]
fn to_blob(data: &[u8]) -> DATA_BLOB {
    DATA_BLOB {
        cbData: data.len() as DWORD,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// Encrypts data using Windows DPAPI
///
/// # Arguments
///
/// * `data` - The data to encrypt
/// * `scope` - The encryption scope (User or Machine)
/// * `entropy` - Optional additional entropy data to strengthen encryption
///
/// # Returns
///
/// Returns a `Result` containing the encrypted data as a `Vec<u8>` if successful.
///
/// # Errors
///
/// Returns an error if:
/// - The Windows API call fails
/// - Memory allocation fails
/// - The current user doesn't have permission to encrypt data
///
/// # Examples
///
/// ```rust
/// use windows_dpapi::{encrypt_data, Scope};
///
/// fn main() -> anyhow::Result<()> {
///     let secret = b"my secret data";
///     let entropy = b"my entropy";
///     let encrypted = encrypt_data(secret, Scope::User, Some(entropy))?;
///     Ok(())
/// }
/// ```
#[cfg(windows)]
pub fn encrypt_data(data: &[u8], scope: Scope, entropy: Option<&[u8]>) -> Result<Vec<u8>> {
    log::debug!("Encrypting with DPAPI ({:?} scope)", scope);

    let flags = match scope {
        Scope::User => 0,      // default = user + UI prompt (but no entropy = silent)
        Scope::Machine => 0x4, // CRYPTPROTECT_LOCAL_MACHINE
    };

    unsafe {
        let mut input = to_blob(data);
        let mut entropy_blob = if let Some(ent) = entropy {
            to_blob(ent)
        } else {
            DATA_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            }
        };

        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let success = CryptProtectData(
            &mut input,
            ptr::null(),
            if entropy.is_some() {
                &mut entropy_blob
            } else {
                ptr::null_mut()
            },
            ptr::null_mut(),
            ptr::null_mut(),
            flags,
            &mut output,
        );

        if success == 0 {
            return Err(std::io::Error::last_os_error()).context("CryptProtectData failed");
        }

        let encrypted = slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        winapi::um::winbase::LocalFree(output.pbData as *mut _);
        Ok(encrypted)
    }
}

/// Decrypts data that was encrypted using Windows DPAPI
///
/// # Arguments
///
/// * `data` - The encrypted data to decrypt
/// * `scope` - The encryption scope that was used to encrypt the data
/// * `entropy` - The optional entropy that was used to encrypt the data
///
/// # Returns
///
/// Returns a `Result` containing the decrypted data as a `Vec<u8>` if successful.
///
/// # Errors
///
/// Returns an error if:
/// - The Windows API call fails
/// - The data is corrupted
/// - The current context does not match the encryption scope (e.g., wrong user or machine)
/// - The current user doesn't have permission to decrypt the data
/// - The data was encrypted on a different machine
///
/// # Examples
///
/// ```rust
/// use windows_dpapi::{encrypt_data, decrypt_data, Scope};
///
/// fn main() -> anyhow::Result<()> {
///     // First encrypt some data
///     let secret = b"my secret data";
///     let entropy = b"my entropy";
///     let encrypted = encrypt_data(secret, Scope::User, Some(entropy))?;
///     
///     // Then decrypt it
///     let decrypted = decrypt_data(&encrypted, Scope::User, Some(entropy))?;
///     assert_eq!(secret, decrypted.as_slice());
///     Ok(())
/// }
/// ```
#[cfg(windows)]
pub fn decrypt_data(data: &[u8], scope: Scope, entropy: Option<&[u8]>) -> Result<Vec<u8>> {
    log::debug!("Decrypting with DPAPI ({:?} scope)", scope);

    let flags = match scope {
        Scope::User => 0,
        Scope::Machine => 0x4,
    };

    unsafe {
        let mut input = to_blob(data);
        let mut entropy_blob = if let Some(ent) = entropy {
            to_blob(ent)
        } else {
            DATA_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            }
        };
        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let success = CryptUnprotectData(
            &mut input,
            ptr::null_mut(),
            if entropy.is_some() {
                &mut entropy_blob
            } else {
                ptr::null_mut()
            },
            ptr::null_mut(),
            ptr::null_mut(),
            flags,
            &mut output,
        );

        if success == 0 {
            return Err(std::io::Error::last_os_error()).context("CryptUnprotectData failed");
        }

        let decrypted = slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        winapi::um::winbase::LocalFree(output.pbData as *mut _);
        Ok(decrypted)
    }
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_user_scope() {
        let original = b"user secret";
        let encrypted = encrypt_data(original, Scope::User, None).expect("User encryption failed");
        assert_ne!(original.to_vec(), encrypted);
        let decrypted =
            decrypt_data(&encrypted, Scope::User, None).expect("User decryption failed");
        assert_eq!(original.to_vec(), decrypted);
    }

    #[test]
    fn round_trip_user_scope_entropy() {
        let original = b"user secret";
        let entropy = b"user entropy";
        let encrypted =
            encrypt_data(original, Scope::User, Some(entropy)).expect("User encryption failed");
        assert_ne!(original.to_vec(), encrypted);
        let decrypted =
            decrypt_data(&encrypted, Scope::User, Some(entropy)).expect("User decryption failed");
        assert_eq!(original.to_vec(), decrypted);
    }

    #[test]
    fn round_trip_machine_scope() {
        let original = b"machine secret";
        let encrypted =
            encrypt_data(original, Scope::Machine, None).expect("Machine encryption failed");
        assert_ne!(original.to_vec(), encrypted);
        let decrypted =
            decrypt_data(&encrypted, Scope::Machine, None).expect("Machine decryption failed");
        assert_eq!(original.to_vec(), decrypted);
    }

    #[test]
    fn round_trip_machine_scope_entropy() {
        let original = b"machine secret";
        let entropy = b"user entropy";
        let encrypted = encrypt_data(original, Scope::Machine, Some(entropy))
            .expect("Machine encryption failed");
        assert_ne!(original.to_vec(), encrypted);
        let decrypted = decrypt_data(&encrypted, Scope::Machine, Some(entropy))
            .expect("Machine decryption failed");
        assert_eq!(original.to_vec(), decrypted);
    }

    #[test]
    fn handles_empty_input() {
        let data = b"";
        let encrypted = encrypt_data(data, Scope::Machine, None).expect("Encrypt empty");
        let decrypted = decrypt_data(&encrypted, Scope::Machine, None).expect("Decrypt empty");
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn handles_empty_input_entropy() {
        let data = b"";
        let entropy = b"random entropy";
        let encrypted = encrypt_data(data, Scope::Machine, Some(entropy)).expect("Encrypt empty");
        let decrypted =
            decrypt_data(&encrypted, Scope::Machine, Some(entropy)).expect("Decrypt empty");
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn handles_empty_entropy() {
        let data = b"random value";
        let entropy = b"";
        let encrypted = encrypt_data(data, Scope::Machine, Some(entropy)).expect("Encrypt empty");
        let decrypted =
            decrypt_data(&encrypted, Scope::Machine, Some(entropy)).expect("Decrypt empty");
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn handles_large_input() {
        let data = vec![0xAAu8; 5 * 1024 * 1024];
        let encrypted = encrypt_data(&data, Scope::Machine, None).expect("Encrypt large");
        let decrypted = decrypt_data(&encrypted, Scope::Machine, None).expect("Decrypt large");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn handles_large_input_entropy() {
        let data = vec![0xAAu8; 5 * 1024 * 1024];
        let entropy = b"random entropy";
        let encrypted = encrypt_data(&data, Scope::Machine, Some(entropy)).expect("Encrypt large");
        let decrypted =
            decrypt_data(&encrypted, Scope::Machine, Some(entropy)).expect("Decrypt large");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn handles_large_entropy() {
        let data = b"Random input";
        let entropy = &vec![0xAAu8; 5 * 1024 * 1024];
        let encrypted = encrypt_data(data, Scope::Machine, Some(entropy)).expect("Encrypt large");
        let decrypted =
            decrypt_data(&encrypted, Scope::Machine, Some(entropy)).expect("Decrypt large");
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn fails_on_corrupted_data() {
        let original = b"important";
        let mut encrypted = encrypt_data(original, Scope::Machine, None).expect("Encrypt failed");
        encrypted[0] ^= 0xFF;
        let result = decrypt_data(&encrypted, Scope::Machine, None);
        assert!(result.is_err(), "Corrupted data should fail");
    }
    #[test]
    fn fails_on_corrupted_data_entropy() {
        let original = b"important";
        let entropy = b"entropy";
        let mut encrypted =
            encrypt_data(original, Scope::Machine, Some(entropy)).expect("Encrypt failed");
        encrypted[0] ^= 0xFF;
        let result = decrypt_data(&encrypted, Scope::Machine, Some(entropy));
        assert!(result.is_err(), "Corrupted data should fail");
    }

    #[test]
    fn fails_on_wrong_entropy() {
        let original = b"user secret";
        let entropy = b"user entropy";
        let bad_entropy = b"bad entropy";
        let encrypted =
            encrypt_data(original, Scope::User, Some(entropy)).expect("User encryption failed");
        assert_ne!(original.to_vec(), encrypted);
        let result = decrypt_data(&encrypted, Scope::User, Some(bad_entropy));
        assert!(result.is_err(), "Wrong entropy should fail");
    }

    #[test]
    fn entropy_encrypts_differently() {
        let original = b"user secret";
        let entropy = b"user entropy";
        let bad_entropy = b"bad entropy";
        let encrypted =
            encrypt_data(original, Scope::User, Some(entropy)).expect("User encryption failed");
        assert_ne!(original.to_vec(), encrypted);
        let other_encrypted =
            encrypt_data(original, Scope::User, Some(bad_entropy)).expect("User encryption failed");
        assert_ne!(encrypted, other_encrypted);
    }
}
