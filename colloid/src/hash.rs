/// This hash mod is based on The Noise Protocol specs: https://noiseprotocol.org/noise.html#hash-functions.

/// Hash output length for blake3.
pub const HASHLEN: usize = blake3::OUT_LEN;
pub const BLOCKLEN: usize = blake3::BLOCK_LEN;

/// Hash the data at once.
pub mod once {
    pub mod rayon {
        use crate::byte;
        use crate::dh::DHLEN;
        use crate::hash::HASHLEN;

        pub fn hash(data: &[u8]) -> blake3::Hash {
            blake3::Hasher::new().update_rayon(data).finalize()
        }

        pub fn hkdf(
            chaining_key: &[u8; HASHLEN],
            input_key_material: &[u8; DHLEN],
            num_out: u8,
            out1: &mut [u8],
            out2: &mut [u8],
            out3: Option<&mut [u8]>,
        ) {
            let mac_temp_key = hmac(chaining_key, input_key_material);
            let temp_key = mac_temp_key.as_bytes();
            let mac_output1 = hmac(temp_key, &byte(1));
            let output1 = mac_output1.as_bytes();
            out1.copy_from_slice(output1);
            let mut buf1 = [0u8; 33];
            buf1[..32].copy_from_slice(output1);
            buf1[32..].copy_from_slice(&byte(2));
            let mac_output2 = hmac(temp_key, &buf1);
            let output2 = mac_output2.as_bytes();
            out2.copy_from_slice(output2);
            if num_out == 2 {
                return;
            }
            if let Some(out3) = out3 {
                let mut buf2 = [0u8; 33];
                buf2[..32].copy_from_slice(output2);
                buf2[32..].copy_from_slice(&byte(3));
                let mac_output3 = hmac(temp_key, &buf2);
                let output3 = mac_output3.as_bytes();
                out3.copy_from_slice(output3);
            };
        }

        pub fn hmac(chaining_key: &[u8; HASHLEN], data: &[u8]) -> blake3::Hash {
            blake3::Hasher::new_keyed(chaining_key)
                .update_rayon(data)
                .finalize()
        }
    }

    pub mod mmap {
        use std::path::PathBuf;

        use crate::byte;
        use crate::dh::DHLEN;
        use crate::hash::HASHLEN;

        pub fn hash(path: PathBuf) -> blake3::Hash {
            blake3::Hasher::new()
                .update_mmap(path)
                .expect("failed to open file.")
                .finalize()
        }

        pub fn hkdf(
            chaining_key: &[u8; HASHLEN],
            input_key_material: &[u8; DHLEN],
            num_out: u8,
            out1: &mut [u8],
            out2: &mut [u8],
            out3: Option<&mut [u8]>,
        ) {
            let mac_temp_key = hmac(chaining_key, input_key_material);
            let temp_key = mac_temp_key.as_bytes();
            let mac_output1 = hmac(temp_key, &byte(1));
            let output1 = mac_output1.as_bytes();
            out1.copy_from_slice(output1);
            let mut buf1 = [0u8; 33];
            buf1[..32].copy_from_slice(output1);
            buf1[32..].copy_from_slice(&byte(2));
            let mac_output2 = hmac(temp_key, &buf1);
            let output2 = mac_output2.as_bytes();
            out2.copy_from_slice(output2);
            if num_out == 2 {
                return;
            }
            if let Some(out3) = out3 {
                let mut buf2 = [0u8; 33];
                buf2[..32].copy_from_slice(output2);
                buf2[32..].copy_from_slice(&byte(3));
                let mac_output3 = hmac(temp_key, &buf2);
                let output3 = mac_output3.as_bytes();
                out3.copy_from_slice(output3);
            };
        }

        pub fn hmac(chaining_key: &[u8; HASHLEN], data: &[u8]) -> blake3::Hash {
            blake3::keyed_hash(chaining_key, data)
        }
    }

    pub mod mmap_rayon {
        use std::path::PathBuf;

        use crate::byte;
        use crate::dh::DHLEN;
        use crate::hash::HASHLEN;

        pub fn hash(path: PathBuf) -> blake3::Hash {
            blake3::Hasher::new()
                .update_mmap_rayon(path)
                .expect("failed to open file")
                .finalize()
        }

        pub fn hkdf(
            chaining_key: &[u8; HASHLEN],
            input_key_material: &[u8; DHLEN],
            num_out: u8,
            out1: &mut [u8],
            out2: &mut [u8],
            out3: Option<&mut [u8]>,
        ) {
            let mac_temp_key = hmac(chaining_key, input_key_material);
            let temp_key = mac_temp_key.as_bytes();
            let mac_output1 = hmac(temp_key, &byte(1));
            let output1 = mac_output1.as_bytes();
            out1.copy_from_slice(output1);
            let mut buf1 = [0u8; 33];
            buf1[..32].copy_from_slice(output1);
            buf1[32..].copy_from_slice(&byte(2));
            let mac_output2 = hmac(temp_key, &buf1);
            let output2 = mac_output2.as_bytes();
            out2.copy_from_slice(output2);
            if num_out == 2 {
                return;
            }
            if let Some(out3) = out3 {
                let mut buf2 = [0u8; 33];
                buf2[..32].copy_from_slice(output2);
                buf2[32..].copy_from_slice(&byte(3));
                let mac_output3 = hmac(temp_key, &buf2);
                let output3 = mac_output3.as_bytes();
                out3.copy_from_slice(output3);
            };
        }

        pub fn hmac(chaining_key: &[u8; HASHLEN], data: &[u8]) -> blake3::Hash {
            blake3::Hasher::new_keyed(chaining_key)
                .update_rayon(data)
                .finalize()
        }
    }
}

pub mod stream {
    use std::io::Read;

    use crate::byte;
    use crate::dh::DHLEN;
    use crate::hash::HASHLEN;

    pub fn hash(reader: impl Read) -> blake3::Hash {
        blake3::Hasher::new()
            .update_reader(reader)
            .expect("failed to read from the reader.")
            .finalize()
    }
    pub fn hkdf(
        chaining_key: &[u8; HASHLEN],
        input_key_material: &[u8; DHLEN],
        // reader: impl Read,
        num_out: u8,
        out1: &mut [u8],
        out2: &mut [u8],
        out3: Option<&mut [u8]>,
    ) {
        let mac_temp_key = hmac(chaining_key, input_key_material);
        let temp_key = mac_temp_key.as_bytes();
        let mac_output1 = hmac(temp_key, &byte(1));
        let output1 = mac_output1.as_bytes();
        out1.copy_from_slice(output1);
        let mut buf1 = [0u8; 33];
        buf1[..32].copy_from_slice(output1);
        buf1[32..].copy_from_slice(&byte(2));
        let mac_output2 = hmac(temp_key, &buf1);
        let output2 = mac_output2.as_bytes();
        out2.copy_from_slice(output2);
        if num_out == 2 {
            return;
        }
        if let Some(out3) = out3 {
            let mut buf2 = [0u8; 33];
            buf2[..32].copy_from_slice(output2);
            buf2[32..].copy_from_slice(&byte(3));
            let mac_output3 = hmac(temp_key, &buf2);
            let output3 = mac_output3.as_bytes();
            out3.copy_from_slice(output3);
        };
    }
    pub fn hmac(chaining_key: &[u8; HASHLEN], data: &[u8]) -> blake3::Hash {
        blake3::Hasher::new_keyed(chaining_key)
            .update_rayon(data)
            .finalize()
    }
}
