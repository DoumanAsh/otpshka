//!Simple and minimalistic `OTP` library.
//!
//!## Feautres
//!
//!- `hotp` - Enables basic hmac implementation.
//!- `totp` - Enables `htop` and time based wrapper for it.
//!- `std`  - Enables std related features like accessing current time.

#![warn(missing_docs)]

#![no_std]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "hotp")]
///Re-export of HMAC algorithms from `ring`
pub use ring::hmac;

#[cfg(feature = "hotp")]
mod hotp;
#[cfg(feature = "hotp")]
pub use hotp::Hotp;
#[cfg(feature = "totp")]
mod totp;
#[cfg(feature = "totp")]
pub use totp::Totp;
