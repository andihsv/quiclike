pub mod cipher;
pub mod dh;
pub mod hash;

#[inline(always)]
pub fn byte(n: u8) -> [u8; 1] {
    [n]
}
