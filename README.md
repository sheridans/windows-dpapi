# windows-dpapi

[![CI](https://github.com/sheridans/windows-dpapi/actions/workflows/ci.yml/badge.svg)](https://github.com/sheridans/windows-dpapi/actions/workflows/ci.yml)
[![Docs](https://docs.rs/windows-dpapi/badge.svg)](https://docs.rs/windows-dpapi)

**Safe Rust wrapper for Windows DPAPI (Data Protection API), supporting both user and machine scope encryption.**


## Features

- Encrypt/decrypt using Windows native APIs
- `Scope::User` and `Scope::Machine` support
- Production-ready, minimal, and memory-safe
- Windows-only (will not compile on other platforms)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
windows-dpapi = "0.2.0"
```

Basic usage:

```rust
use windows_dpapi::{encrypt_data, decrypt_data, Scope};

fn main() -> anyhow::Result<()> {
    let secret = b"my secret";
    let encrypted = encrypt_data(secret, Scope::User, None)?;
    let decrypted = decrypt_data(&encrypted, Scope::User, None)?;
    assert_eq!(secret, decrypted.as_slice());
    Ok(())
}
```

## Security Considerations

### User Scope
- Data is encrypted using the current user's credentials
- Only the same user on the same machine can decrypt the data
- If the user's password changes, the data can still be decrypted
- If the user is deleted, the data cannot be decrypted

### Machine Scope
- Data is encrypted using the machine's credentials
- Any user on the same machine can decrypt the data
- Useful for shared secrets that need to be accessible to all users
- Less secure than user scope as it's accessible to all local users

## Common Use Cases

- Storing application secrets
- Securing user credentials
- Protecting sensitive configuration data
- Any Windows application that needs to store sensitive data securely

## Limitations

- Windows-only (this crate will not compile on other platforms)
- Data cannot be decrypted on a different machine
- Machine scope is less secure than user scope

## License

This project is licensed under either of the following, at your option:

- [MIT License](LICENSE-MIT) ([SPDX: MIT](http://opensource.org/licenses/MIT))
- [Apache License 2.0](LICENSE-APACHE) ([SPDX: Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0))

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
