pub mod cipher;
pub mod dh;
pub mod hash;
pub use blake3;

#[inline(always)]
pub fn byte(n: u8) -> [u8; 1] {
    [n]
}
