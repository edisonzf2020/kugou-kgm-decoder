//! 网易云音乐 NCM 格式解码器
//!
//! NCM 文件结构：
//! 1. 魔数头（10字节）：CTENFDAM + 2字节填充
//! 2. 密钥块：AES-128-ECB 加密的 RC4 密钥
//! 3. 元数据块：AES-128-ECB 加密的 JSON 元数据
//! 4. CRC 校验（4字节）+ 5字节未知数据
//! 5. 专辑封面
//! 6. 音频数据：RC4 变种加密

use std::io::Read;

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;

use super::Decoder;

/// NCM 魔数头
const NCM_MAGIC: &[u8; 8] = b"CTENFDAM";

/// AES 核心密钥（用于解密 RC4 密钥）
const CORE_KEY: &[u8; 16] = &[
    0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 
    0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57,
]; // "hzHRAmso5kInbaxW"

/// AES 元数据密钥（用于解密元数据）
#[allow(dead_code)]
const META_KEY: &[u8; 16] = &[
    0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 
    0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28,
]; // "#14ljk_!\]&0U<'("

pub struct Ncm<'a> {
    origin: Box<dyn Read + 'a>,
    key_stream: [u8; 256],  // RC4 密钥流
    pos: usize,
}

impl<'a> Ncm<'a> {
    /// AES-128-ECB 解密（带 PKCS7 去填充）
    fn aes_ecb_decrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
        let cipher = Aes128::new(key.into());
        let mut result = data.to_vec();
        
        // 按 16 字节块解密
        for chunk in result.chunks_exact_mut(16) {
            let block = aes::Block::from_mut_slice(chunk);
            cipher.decrypt_block(block);
        }
        
        // 去除 PKCS7 填充
        if let Some(&padding) = result.last() {
            let padding = padding as usize;
            if padding > 0 && padding <= 16 && result.len() >= padding {
                result.truncate(result.len() - padding);
            }
        }
        
        result
    }

    /// 读取长度前缀的数据块
    fn read_block(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data)?;
        Ok(data)
    }

    /// 初始化 RC4 密钥流（NCM 使用的 RC4 变种）
    fn init_key_stream(rc4_key: &[u8]) -> [u8; 256] {
        // SBOX 初始化
        let mut s: [u8; 256] = [0; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        // 初始替换
        let mut j: usize = 0;
        for i in 0..256 {
            j = (j + s[i] as usize + rc4_key[i % rc4_key.len()] as usize) & 255;
            s.swap(i, j);
        }

        // 生成密钥流（NCM 特有的变种算法）
        let mut key_stream = [0u8; 256];
        for i in 0..256 {
            let a = (i + 1) & 255;
            let b = s[(a + s[a] as usize) & 255] as usize;
            key_stream[i] = s[(s[a] as usize + b) & 255];
        }

        key_stream
    }
}


impl<'a> Decoder<'a> for Ncm<'a> {
    fn new(origin: impl Read + 'a) -> Self {
        match Ncm::try_new(origin) {
            Some(val) => val,
            None => panic!("Invalid NCM data"),
        }
    }

    fn decodeable_length_interval() -> (u64, u64) {
        (0, u64::MAX)
    }

    fn try_new(mut origin: impl Read + 'a) -> Option<Self> {
        // 1. 验证魔数头
        let mut magic = [0u8; 10];
        if origin.read_exact(&mut magic).is_err() {
            return None;
        }
        if &magic[..8] != NCM_MAGIC {
            return None;
        }

        // 2. 读取并解密 RC4 密钥
        let key_data = match Self::read_block(&mut origin) {
            Ok(data) => data,
            Err(_) => return None,
        };

        // XOR 0x64
        let key_data: Vec<u8> = key_data.iter().map(|b| b ^ 0x64).collect();
        
        // AES-ECB 解密
        let rc4_key = Self::aes_ecb_decrypt(&key_data, CORE_KEY);
        
        // 去除前 17 字节 "neteasecloudmusic"
        if rc4_key.len() <= 17 {
            return None;
        }
        let rc4_key = &rc4_key[17..];

        // 3. 跳过元数据块
        if Self::read_block(&mut origin).is_err() {
            return None;
        }

        // 4. 跳过 CRC（4字节）+ 5字节未知数据
        let mut skip = [0u8; 9];
        if origin.read_exact(&mut skip).is_err() {
            return None;
        }

        // 5. 跳过封面图片
        if Self::read_block(&mut origin).is_err() {
            // 封面可能不存在，忽略错误
        }

        // 6. 初始化 RC4 密钥流
        let key_stream = Self::init_key_stream(rc4_key);

        Some(Ncm {
            origin: Box::new(origin),
            key_stream,
            pos: 0,
        })
    }
}

impl Read for Ncm<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.origin.read(buf)?;
        
        // 使用密钥流解密
        for i in 0..len {
            buf[i] ^= self.key_stream[(self.pos + i) % 256];
        }
        
        self.pos += len;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ecb_decrypt() {
        // 简单测试 AES 解密功能
        let key: [u8; 16] = [0; 16];
        let data = [0u8; 16];
        let result = Ncm::aes_ecb_decrypt(&data, &key);
        assert!(!result.is_empty());
    }
}
