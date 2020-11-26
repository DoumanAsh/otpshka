use crate::hotp::HOTP;

use super::Algorithm;

#[cfg(feature = "std")]
fn current_time_s() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH)
                     .expect("now should be after epoch")
                     .as_secs()
}

#[derive(Clone)]
///Modification of `Htop` algorithm that uses unix timestamp within `window`
pub struct TOTP {
    ///Basic HMAC OTP algorithm, which is used as corner-stone of TOTP.
    inner: HOTP,
    ///Number of seconds allowed as network delay.
    ///
    ///Default and recommended is 1.
    pub skew: u8,
    ///Time window in seconds.
    ///
    ///Default and recommended is 30.
    pub window: u64,
}

impl TOTP {
    #[inline]
    ///Initializes algorithm using provided `algorithm` and `secret`
    ///
    ///- `algorithm` - Generally acceptable are HMAC based on `sha-1`, `sha-256` and `sha-512`
    ///- `secret` - Raw bytes used to derive HMAC key. User is responsible to decode it before
    ///passing.
    pub fn new<T: AsRef<[u8]>>(algorithm: Algorithm, secret: T) -> Self {
        Self {
            inner: HOTP::new(algorithm, secret),
            skew: 1,
            window: 30,
        }
    }

    #[inline(always)]
    ///Signs provided `time` value using stored HMAC key.
    pub fn sign(&self, time: u64) -> impl AsRef<[u8]> + Clone + Copy {
        self.inner.sign(time / self.window)
    }

    #[inline(always)]
    ///Generates password as number from provided `counter` value with length of `digits`.
    ///
    ///Note that in this case you must handle missing padding yourself.
    pub fn generate_num(&self, time: u64, digits: u8) -> u32 {
        self.inner.generate_num(time / self.window, digits)
    }

    #[inline(always)]
    ///Generates pass based on provided `time` and writes it into provided `dest`.
    ///
    ///This always writes `dest.as_ref().len()`.
    ///
    ///Recommended buffer length is be within `6..8`
    pub fn generate_to<T: AsMut<[u8]>>(&self, time: u64, dest: T) {
        self.inner.generate_to(time / self.window, dest)
    }

    #[cfg(feature = "std")]
    #[inline(always)]
    ///Generates pass using current system time from `std`
    pub fn generate_to_now<T: AsMut<[u8]>>(&self, dest: T) {
        self.generate_to(current_time_s(), dest)
    }

    #[inline]
    ///Checks whether provided `token` corresponds to `time`.
    pub fn verify(&self, token: &str, time: u64) -> bool {
        debug_assert!(token.len() <= u8::max_value() as _);

        let expected = match u32::from_str_radix(token, 10) {
            Ok(expected) => expected,
            Err(_) => return false,
        };

        if self.inner.generate_num(time / self.window, token.len() as u8) == expected {
            return true;
        }

        for time_offset in 1..=self.skew as u64 {
            if self.inner.generate_num((time + time_offset) / self.window, token.len() as u8) == expected {
                return true;
            }

            if self.inner.generate_num((time - time_offset) / self.window, token.len() as u8) == expected {
                return true;
            }
        }

        false
    }

    #[cfg(feature = "std")]
    #[inline]
    ///Checks whether provided `token` corresponds to current system time.
    pub fn verify_now(&self, token: &str) -> bool {
        self.verify(token, current_time_s())
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
        let totp = TOTP::new(Default::default(), secret);

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
        let totp = TOTP::new(Default::default(), secret);

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

    #[cfg(feature = "std")]
    #[test]
    fn should_test_totp_now() {
        let secret = [72, 101, 108, 108, 111, 33, 222, 173, 190, 239];
        let totp = TOTP::new(Default::default(), secret);

        let mut token1 = [0u8, 0, 0, 0, 0, 0];
        totp.generate_to_now(&mut token1[..]);
        let token1 = core::str::from_utf8(&token1).expect("UTF-8 compatible output");
        assert!(totp.verify_now(token1));

        let mut token2 = [0u8, 0, 0, 0, 0, 0];
        std::thread::sleep(core::time::Duration::from_secs(1));
        totp.generate_to_now(&mut token2[..]);
        let token2 = core::str::from_utf8(&token2).expect("UTF-8 compatible output");
        assert!(totp.verify_now(token2));

        assert_eq!(token1, token2);
        assert!(totp.verify_now(token1));
    }
}
