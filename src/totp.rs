//!Time based algorithm
//!
//!Algorithm relies on time as source uniqueness.
//!Library makes no attempt to force source, hence user must manually provide UNIX time to generate
//!password.

///Re-export of HMAC algorithms from `ring`
pub use ring::hmac;

use crate::hotp::Hotp;

#[derive(Clone)]
///Algorithm representation
pub struct Totp {
    ///Basic HMAC OTP algorithm, which is used as basis.
    pub inner: Hotp,
    ///Number of steps allowed as network delay.
    ///
    ///Default and recommended is 1.
    pub skew: u8,
    ///Duration in seconds of a step.
    ///
    ///Default and recommended is 30.
    pub step: u64,
}

impl Totp {
    #[inline]
    ///Initializes algorithm using provided `algorithm` and `secret`
    ///
    ///- `algorithm` - Generally acceptable are HMAC based on `sha-1`, `sha-256` and `sha-512`
    ///- `secret` - Raw bytes used to derive HMAC key. User is responsible to decode it before
    ///passing.
    pub fn new<T: AsRef<[u8]>>(algorithm: hmac::Algorithm, secret: T) -> Self {
        Self {
            inner: Hotp::new(algorithm, secret),
            skew: 1,
            step: 30,
        }
    }

    #[inline(always)]
    ///Signs provided `time` value using stored HMAC key.
    pub fn sign(&self, time: u64) -> impl AsRef<[u8]> + Clone + Copy {
        self.inner.sign(time / self.step)
    }

    #[inline(always)]
    ///Generates digest based on provided `time` and writes it into provided `dest`.
    ///
    ///This always writes `dest.as_ref().len()`.
    ///
    ///Recommended buffer length is be within `6..8`
    pub fn generate_to<T: AsMut<[u8]>>(&self, time: u64, dest: T) {
        self.inner.generate_to(time / self.step, dest)
    }

    #[inline]
    ///Checks whether provided `token` corresponds to `time`.
    pub fn verify(&self, token: &str, time: u64) -> bool {
        debug_assert!(token.len() <= u8::max_value() as _);

        let expected = match u32::from_str_radix(token, 10) {
            Ok(expected) => expected,
            Err(_) => return false,
        };

        if self.inner.generate_num(time / self.step, token.len() as u8) == expected {
            return true;
        }

        for time_offset in 1..=self.skew as u64 {
            if self.inner.generate_num((time + time_offset) / self.step, token.len() as u8) == expected {
                return true;
            }

            if self.inner.generate_num((time - time_offset) / self.step, token.len() as u8) == expected {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_test_totp_window() {
        let input = [
            (30, "996554"),
            (60, "602287"),
        ];

        let secret = [72, 101, 108, 108, 111, 33, 222, 173, 190, 239];
        let totp = Totp::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);

        for (time, expected) in input.iter() {
            let mut output = [0u8, 0, 0, 0, 0, 0];
            assert_eq!(output.len(), expected.len());

            totp.generate_to(*time, &mut output[..]);
            let token = core::str::from_utf8(&output).expect("UTF-8 compatible output");
            assert_eq!(token, *expected);
            assert!(totp.verify(token, *time));
            assert!(totp.verify(token, *time + 30));
            assert!(totp.verify(token, *time - 1));
        }
    }
    #[test]
    fn should_test_totp() {
        let input = [
            (1606206826, "458443"),
            (1606206917, "779542"),
            (1606206950, "082772"),
        ];

        let secret = [72, 101, 108, 108, 111, 33, 222, 173, 190, 239];
        let totp = Totp::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);

        for (time, expected) in input.iter() {
            let mut output = [0u8, 0, 0, 0, 0, 0];
            assert_eq!(output.len(), expected.len());

            totp.generate_to(*time, &mut output[..]);
            let token = core::str::from_utf8(&output).expect("UTF-8 compatible output");
            assert_eq!(token, *expected);
            assert!(totp.verify(token, *time));
            assert!(totp.verify(token, *time + 10));
            assert!(totp.verify(token, *time - 10));
        }
    }
}
