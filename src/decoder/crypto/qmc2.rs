//! QMC2 解密算法实现
//! KGG 文件使用 QMC2 算法加密音频数据

use super::rc4::Rc4;
use super::tea;

const EKEY_V2_PREFIX: &[u8] = b"UVFNdXNpYyBFbmNWMixLZXk6";
const EKEY_V2_KEY1: [u8; 16] = [
    0x33, 0x38, 0x36, 0x5A, 0x4A, 0x59, 0x21, 0x40,
    0x23, 0x2A, 0x24, 0x25, 0x5E, 0x26, 0x29, 0x28,
];
const EKEY_V2_KEY2: [u8; 16] = [
    0x2A, 0x2A, 0x23, 0x21, 0x28, 0x23, 0x24, 0x25,
    0x26, 0x5E, 0x61, 0x31, 0x63, 0x5A, 0x2C, 0x54,
];

/// 将字节数组转换为 u32 数组（小端序）
fn bytes_to_u32_key(bytes: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
    ]
}

/// 解密 ekey v1
fn decrypt_ekey_v1(ekey: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(ekey).ok()?;
    
    if decoded.len() < 8 {
        return None;
    }

    let tea_key: [u32; 4] = [
        0x69005600 | ((decoded[0] as u32) << 16) | (decoded[1] as u32),
        0x46003800 | ((decoded[2] as u32) << 16) | (decoded[3] as u32),
        0x2b002000 | ((decoded[4] as u32) << 16) | (decoded[5] as u32),
        0x15000b00 | ((decoded[6] as u32) << 16) | (decoded[7] as u32),
    ];

    let decrypted = tea::cbc_decrypt(&decoded[8..], &tea_key)?;
    
    let mut result = decoded[..8].to_vec();
    result.extend(decrypted);
    Some(result)
}

/// 解密 ekey v2
fn decrypt_ekey_v2(ekey: &[u8]) -> Option<Vec<u8>> {
    let key1 = bytes_to_u32_key(&EKEY_V2_KEY1);
    let key2 = bytes_to_u32_key(&EKEY_V2_KEY2);
    
    let result = tea::cbc_decrypt(ekey, &key1)?;
    let result = tea::cbc_decrypt(&result, &key2)?;
    decrypt_ekey_v1(&result)
}

/// 解密 ekey
pub fn decrypt_ekey(ekey: &str) -> Option<Vec<u8>> {
    let ekey_bytes = ekey.as_bytes();
    
    if ekey_bytes.starts_with(EKEY_V2_PREFIX) {
        decrypt_ekey_v2(&ekey_bytes[EKEY_V2_PREFIX.len()..])
    } else {
        decrypt_ekey_v1(ekey_bytes)
    }
}

/// QMC2 解密器 trait
pub trait Qmc2Decryptor: Send + Sync {
    fn decrypt(&self, data: &mut [u8], offset: usize);
}

/// QMC2 MAP 模式解密器（密钥长度 < 300）
pub struct Qmc2Map {
    key: [u8; 128],
}

impl Qmc2Map {
    const MAP_OFFSET_BOUNDARY: usize = 0x7FFF;
    const MAP_INDEX_OFFSET: usize = 71214;

    pub fn new(key: &[u8]) -> Self {
        let n = key.len();
        let mut mapped_key = [0u8; 128];
        
        for i in 0..128 {
            let j = (i * i + Self::MAP_INDEX_OFFSET) % n;
            let shift = (j + 4) % 8;
            mapped_key[i] = (key[j] << shift) | (key[j] >> (8 - shift));
        }
        
        Qmc2Map { key: mapped_key }
    }
}

impl Qmc2Decryptor for Qmc2Map {
    fn decrypt(&self, data: &mut [u8], mut offset: usize) {
        for byte in data.iter_mut() {
            let idx = if offset <= Self::MAP_OFFSET_BOUNDARY {
                offset
            } else {
                offset % Self::MAP_OFFSET_BOUNDARY
            };
            *byte ^= self.key[idx % self.key.len()];
            offset += 1;
        }
    }
}

/// QMC2 RC4 模式解密器（密钥长度 >= 300）
pub struct Qmc2Rc4 {
    key: Vec<u8>,
    hash: f64,
    key_stream: Vec<u8>,
}

impl Qmc2Rc4 {
    const FIRST_SEGMENT_SIZE: usize = 0x0080;
    const OTHER_SEGMENT_SIZE: usize = 0x1400;
    const RC4_STREAM_SIZE: usize = Self::OTHER_SEGMENT_SIZE + 512;

    pub fn new(key: &[u8]) -> Self {
        let hash = Self::hash(key);
        let key = key.to_vec();
        
        let mut rc4 = Rc4::new(&key);
        let mut key_stream = vec![0u8; Self::RC4_STREAM_SIZE];
        rc4.generate_stream(&mut key_stream);
        
        Qmc2Rc4 { key, hash, key_stream }
    }

    fn hash(key: &[u8]) -> f64 {
        let mut hash: u32 = 1;
        for &byte in key {
            if byte == 0 {
                continue;
            }
            let next_hash = hash.wrapping_mul(byte as u32);
            if next_hash <= hash {
                break;
            }
            hash = next_hash;
        }
        hash as f64
    }

    #[inline]
    fn get_segment_key(key_hash: f64, segment_id: usize, seed: u8) -> usize {
        if seed == 0 {
            return 0;
        }
        let result = key_hash / (seed as f64 * (segment_id + 1) as f64) * 100.0;
        result as usize
    }

    fn decrypt_first_segment(&self, data: &mut [u8], mut offset: usize) -> usize {
        let n = self.key.len();
        let process_len = std::cmp::min(data.len(), Self::FIRST_SEGMENT_SIZE - offset);
        
        for byte in data[..process_len].iter_mut() {
            let idx = Self::get_segment_key(self.hash, offset, self.key[offset % n]) % n;
            *byte ^= self.key[idx];
            offset += 1;
        }
        
        process_len
    }

    fn decrypt_other_segment(&self, data: &mut [u8], offset: usize) -> usize {
        let n = self.key.len();
        let segment_idx = offset / Self::OTHER_SEGMENT_SIZE;
        let segment_offset = offset % Self::OTHER_SEGMENT_SIZE;
        
        let skip_len = Self::get_segment_key(self.hash, segment_idx, self.key[segment_idx % n]) & 0x1FF;
        let process_len = std::cmp::min(data.len(), Self::OTHER_SEGMENT_SIZE - segment_offset);
        
        for (i, byte) in data[..process_len].iter_mut().enumerate() {
            *byte ^= self.key_stream[skip_len + segment_offset + i];
        }
        
        process_len
    }
}

impl Qmc2Decryptor for Qmc2Rc4 {
    fn decrypt(&self, data: &mut [u8], mut offset: usize) {
        let mut remaining = data;
        
        if offset < Self::FIRST_SEGMENT_SIZE {
            let n = self.decrypt_first_segment(remaining, offset);
            offset += n;
            remaining = &mut remaining[n..];
        }
        
        while !remaining.is_empty() {
            let n = self.decrypt_other_segment(remaining, offset);
            offset += n;
            remaining = &mut remaining[n..];
        }
    }
}

/// 创建 QMC2 解密器
pub fn create_decryptor(ekey: &str) -> Option<Box<dyn Qmc2Decryptor>> {
    let key = decrypt_ekey(ekey)?;
    
    if key.is_empty() {
        return None;
    }
    
    if key.len() < 300 {
        Some(Box::new(Qmc2Map::new(&key)))
    } else {
        Some(Box::new(Qmc2Rc4::new(&key)))
    }
}
