
/// [DOC]: https://noiseprotocol.org/noise.html#crypto-functions
pub mod crypto;
pub mod cipher; 
pub mod dh;
pub mod hash;

use bytes::{BufMut, BytesMut};

pub fn bytes(n: u8) -> BytesMut {
    let mut bytes = BytesMut::with_capacity(1);
    bytes.put_u8(n);
    bytes
}
