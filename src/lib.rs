//!Simple and minimalistic `OTP` library.
//!
//!## Feautres
//!
//!- `std`  - Enables std related features like accessing current time.

#![warn(missing_docs)]

#![no_std]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

use ring::hmac;

///Standard algorithms compatible with `OTP`
pub enum Algorithm {
    ///SHA-1. Default algorithm.
    SHA1,
    ///SHA-256
    SHA256,
    ///SHA-512
    SHA512,
}

impl Default for Algorithm {
    #[inline(always)]
    fn default() -> Self {
        Algorithm::SHA1
    }
}

impl Into<hmac::Algorithm> for Algorithm {
    #[inline(always)]
    fn into(self) -> hmac::Algorithm {
        match self {
            Algorithm::SHA1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::SHA256 => hmac::HMAC_SHA256,
            Algorithm::SHA512 => hmac::HMAC_SHA512,
        }
    }
}

#[cfg(feature = "std")]
extern crate std;

mod hotp;
pub use hotp::HOTP;
mod totp;
pub use totp::TOTP;
