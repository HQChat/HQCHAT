//! Message padding: a payload's plaintext is grown to a multiple of
//! [`BLOCK`] bytes before it is sealed, so the server and the network see
//! which size class a message falls in, not its length. ISO/IEC 7816-4
//! (one `0x80`, then zeros), so the end of the text is unambiguous whatever
//! it holds. A frame says it is padded with the header's padded flag, which
//! the AAD binds.

use crate::Error;

/// The size class, in bytes.
pub const BLOCK: usize = 256;

/// `plain`, grown to the next multiple of [`BLOCK`] after its marker byte.
pub fn pad(plain: &[u8]) -> Vec<u8> {
    let marked = plain.len().saturating_add(1);
    let padded = marked.div_ceil(BLOCK).saturating_mul(BLOCK);
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(plain);
    out.push(0x80);
    out.resize(padded, 0);
    out
}

/// The plaintext [`pad`] grew, or an error for anything it could not have
/// produced (no marker, a length off the block size).
pub fn unpad(padded: &[u8]) -> Result<&[u8], Error> {
    if padded.is_empty() || !padded.len().is_multiple_of(BLOCK) {
        return Err(Error::Malformed("padding: not a whole number of blocks"));
    }
    let end = padded
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::Malformed("padding: no marker"))?;
    if padded.get(end) != Some(&0x80) || padded.len().saturating_sub(end) > BLOCK {
        return Err(Error::Malformed("padding: no marker"));
    }
    padded
        .get(..end)
        .ok_or(Error::Malformed("padding: no marker"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_fall_into_size_classes_and_round_trip() {
        for (len, class) in [(0, 256), (1, 256), (255, 256), (256, 512), (1000, 1024)] {
            let text = vec![0x80u8; len];
            let p = pad(&text);
            assert_eq!(p.len(), class, "{len}");
            assert_eq!(unpad(&p).unwrap(), text.as_slice());
        }
    }

    #[test]
    fn what_pad_cannot_produce_is_refused() {
        assert!(unpad(&[]).is_err());
        assert!(unpad(&[0; 256]).is_err(), "no marker");
        assert!(unpad(&[1; 255]).is_err(), "not a whole block");
        let mut p = pad(b"hi");
        p[255] = 1;
        assert!(unpad(&p).is_err(), "a byte after the marker");
        let mut long = vec![0x80];
        long.resize(512, 0);
        assert!(
            unpad(&long).is_err(),
            "a whole block of nothing but padding"
        );
    }
}
