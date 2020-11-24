use core::{mem, ptr};

///Re-export of HMAC algorithms from `ring`
use ring::hmac;

#[derive(Clone)]
///HMAC based OTP algorithm that uses simple counter as input.
pub struct Hotp {
    ///HMAC key generated using `algorithm` and `secret`
    ///
    ///See `new` for details
    pub key: hmac::Key,
}

impl Hotp {
    #[inline]
    ///Initializes algorithm using provided `algorithm` and `secret`
    ///
    ///- `algorithm` - Generally acceptable are HMAC based on `sha-1`, `sha-256` and `sha-512`
    ///- `secret` - Raw bytes used to derive HMAC key. User is responsible to decode it before
    ///passing.
    pub fn new<T: AsRef<[u8]>>(algorithm: hmac::Algorithm, secret: T) -> Self {
        let secret = secret.as_ref();
        debug_assert_ne!(secret.len(), 0);

        Self {
            key: hmac::Key::new(algorithm, secret),
        }
    }

    #[inline]
    ///Signs provided `time` value using stored HMAC key.
    pub fn sign(&self, counter: u64) -> impl AsRef<[u8]> + Clone + Copy {
        let counter = counter.to_be_bytes();

        hmac::sign(&self.key, &counter)
    }

    pub(crate) fn generate_num(&self, counter: u64, digits: u8) -> u32 {
        const BASE: u32 = 10;

        let sign = self.sign(counter);
        let sign = sign.as_ref();

        let offset = (sign[sign.len() - 1] & 15) as usize;
        debug_assert!(offset + mem::size_of::<u32>() < sign.len());

        let snum = unsafe {
            let mut snum = mem::MaybeUninit::<u32>::uninit();
            ptr::copy_nonoverlapping(sign.as_ptr().add(offset), snum.as_mut_ptr() as _, 4);
            snum.assume_init().to_be() & 0x7fff_ffff
        };

        snum % BASE.pow(digits as u32)
    }

    unsafe fn generate_to_ptr(&self, counter: u64, dest: *mut u8, len: usize) {
        use core::fmt::{self, Write};

        struct WriteBuffer(*mut u8, usize);
        impl Write for WriteBuffer {
            #[inline]
            fn write_str(&mut self, text: &str) -> fmt::Result {
                //write! can call it multiple times hence remember
                let written_len = text.len();
                debug_assert!(written_len <= self.1);

                unsafe {
                    ptr::copy_nonoverlapping(text.as_ptr(), self.0, written_len);
                    self.0 = self.0.add(written_len);
                }
                self.1 = self.1 - written_len;

                Ok(())
            }
        }

        debug_assert_ne!(len, 0);
        debug_assert!(len <= u8::max_value() as _);
        debug_assert!(!dest.is_null());

        let snum = self.generate_num(counter, len as u8);

        let mut buffer = WriteBuffer(dest, len);
        let _ = write!(buffer, "{:0width$}", snum, width = len);
    }

    #[inline]
    ///Generates digest based on provided `time` and writes it into provided `dest`.
    ///
    ///This always writes `dest.as_ref().len()`.
    ///
    ///Recommended buffer length is be within `6..8`
    pub fn generate_to<T: AsMut<[u8]>>(&self, time: u64, mut dest: T) {
        let dest = dest.as_mut();
        unsafe {
            self.generate_to_ptr(time, dest.as_mut_ptr(), dest.len())
        }
    }

    ///Checks whether provided `token` corresponds to `counter`.
    pub fn verify(&self, token: &str, counter: u64) -> bool {
        debug_assert!(token.len() <= u8::max_value() as _);

        let expected = match u32::from_str_radix(token, 10) {
            Ok(expected) => expected,
            Err(_) => return false,
        };

        self.generate_num(counter, token.len() as u8) == expected
    }
}
