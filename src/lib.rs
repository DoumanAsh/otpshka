//!Simple and minimalistic `OTP` library.
//!
//!## Feautres
//!
//!- `hotp` - Enables basic hmac implementation.
//!- `totp` - Enables `htop` and time based wrapper for it.

#![warn(missing_docs)]

#![no_std]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

#[cfg(feature = "hotp")]
pub mod hotp;
#[cfg(feature = "totp")]
pub mod totp;
