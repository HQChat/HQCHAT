//! Checked reading and writing of wire bytes. Every read that would run past
//! the end is [`Error::Malformed`], every length that does not fit its field
//! is [`Error::Invalid`]. The decoders read through [`Reader`] alone, so no
//! input can make them index out of bounds, panic or wrap.

use crate::Error;

/// A cursor over untrusted bytes.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    rest: &'a [u8],
    truncated: &'static str,
}

impl<'a> Reader<'a> {
    /// Reads `bytes`; a short read fails with `Malformed(truncated)`.
    pub fn new(bytes: &'a [u8], truncated: &'static str) -> Self {
        Self {
            rest: bytes,
            truncated,
        }
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(Error::Malformed(self.truncated))?;
        self.rest = tail;
        Ok(head)
    }

    /// The next `N` bytes as an array.
    pub fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(Error::Malformed(self.truncated))?;
        self.rest = tail;
        Ok(head)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, Error> {
        let [b] = *self.array::<1>()?;
        Ok(b)
    }

    /// A big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(*self.array()?))
    }

    /// A big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(*self.array()?))
    }

    /// A big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(*self.array()?))
    }

    /// How many bytes are left.
    pub fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// Whether every byte has been read.
    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The bytes not read yet, consuming the reader.
    pub fn rest(self) -> &'a [u8] {
        self.rest
    }

    /// Succeeds only when every byte has been read.
    pub fn finish(self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes"))
        }
    }
}

/// `n` as a one-byte length, or `Invalid(what)`.
pub fn len_u8(n: usize, what: &'static str) -> Result<u8, Error> {
    u8::try_from(n).map_err(|_| Error::Invalid(what))
}

/// `n` as a two-byte length, or `Invalid(what)`.
pub fn len_u16(n: usize, what: &'static str) -> Result<u16, Error> {
    u16::try_from(n).map_err(|_| Error::Invalid(what))
}

/// `n` as a four-byte length, or `Invalid(what)`.
pub fn len_u32(n: usize, what: &'static str) -> Result<u32, Error> {
    u32::try_from(n).map_err(|_| Error::Invalid(what))
}

/// A length known at compile time as a big-endian `u32` prefix. Used in a
/// `const`, a length that does not fit fails the build instead of wrapping.
pub const fn prefix_u32(n: usize) -> [u8; 4] {
    assert!(n <= 0xffff_ffff, "length does not fit a u32 prefix");
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "the assertion above proves the value fits; const fns cannot call try_from"
    )]
    let n = n as u32;
    n.to_be_bytes()
}

/// The first `N` bytes of an `M`-byte array; `N > M` fails the build.
pub fn prefix<const N: usize, const M: usize>(bytes: &[u8; M]) -> [u8; N] {
    const { assert!(N <= M, "prefix longer than its source") };
    let mut out = [0u8; N];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    out
}

/// A wire length as `usize`. Every supported target has a pointer of at
/// least 32 bits, which the assertion below holds at compile time.
pub fn usize_from(n: u32) -> usize {
    const _: () = assert!(usize::BITS >= u32::BITS);
    // Lossless by the assertion above; `try_from` cannot fail here.
    usize::try_from(n).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stop_at_the_end() {
        let mut r = Reader::new(&[1, 0, 2, 0, 0, 3], "short");
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 2);
        assert_eq!(r.u32(), Err(Error::Malformed("short")));
        assert_eq!(r.remaining(), 3, "a failed read consumes nothing");
        assert_eq!(r.take(3).unwrap(), &[0, 0, 3]);
        assert!(r.finish().is_ok());
    }

    #[test]
    fn trailing_bytes_fail_finish() {
        let mut r = Reader::new(&[1, 2], "short");
        r.u8().unwrap();
        assert_eq!(r.finish(), Err(Error::Malformed("trailing bytes")));
    }

    #[test]
    fn lengths_refuse_what_does_not_fit() {
        assert_eq!(len_u8(255, "x"), Ok(255));
        assert_eq!(len_u8(256, "x"), Err(Error::Invalid("x")));
        assert_eq!(len_u16(65_536, "x"), Err(Error::Invalid("x")));
    }
}
