//! TEA (Tiny Encryption Algorithm) 实现
//! 用于 QMC2 ekey 解密

const TEA_ROUNDS: usize = 16;
const TEA_ROUND_DELTA: u32 = 0x9e3779b9;
const TEA_EXPECTED_SUM: u32 = (TEA_ROUNDS as u32).wrapping_mul(TEA_ROUND_DELTA);
const TEA_BLOCK_SIZE: usize = 8;
const FIXED_SALT_LEN: usize = 2;
const ZERO_PAD_LEN: usize = 7;

/// TEA 单轮运算
#[inline]
fn tea_single_round(value: u32, sum: u32, key1: u32, key2: u32) -> u32 {
    ((value << 4).wrapping_add(key1)) ^ (value.wrapping_add(sum)) ^ ((value >> 5).wrapping_add(key2))
}

/// TEA ECB 解密
#[inline]
pub fn ecb_decrypt(value: u64, key: &[u32; 4]) -> u64 {
    let mut y = (value >> 32) as u32;
    let mut z = value as u32;
    let mut sum = TEA_EXPECTED_SUM;

    for _ in 0..TEA_ROUNDS {
        z = z.wrapping_sub(tea_single_round(y, sum, key[2], key[3]));
        y = y.wrapping_sub(tea_single_round(z, sum, key[0], key[1]));
        sum = sum.wrapping_sub(TEA_ROUND_DELTA);
    }

    ((y as u64) << 32) | (z as u64)
}

/// 大端序读取 u64
#[inline]
fn be_read_u64(data: &[u8]) -> u64 {
    u64::from_be_bytes(data[..8].try_into().unwrap())
}

/// 大端序写入 u64
#[inline]
fn be_write_u64(data: &mut [u8], value: u64) {
    data[..8].copy_from_slice(&value.to_be_bytes());
}

/// TEA CBC 解密单轮
fn decrypt_round(p_plain: &mut [u8], p_cipher: &[u8], iv1: &mut u64, iv2: &mut u64, key: &[u32; 4]) {
    let iv1_next = be_read_u64(p_cipher);
    let iv2_next = ecb_decrypt(iv1_next ^ *iv2, key);
    let plain = iv2_next ^ *iv1;
    *iv1 = iv1_next;
    *iv2 = iv2_next;
    be_write_u64(p_plain, plain);
}

/// TEA CBC 解密
pub fn cbc_decrypt(cipher: &[u8], key: &[u32; 4]) -> Option<Vec<u8>> {
    // 至少需要 2 个块
    if cipher.len() % TEA_BLOCK_SIZE != 0 || cipher.len() < TEA_BLOCK_SIZE * 2 {
        return None;
    }

    let mut iv1: u64 = 0;
    let mut iv2: u64 = 0;
    let mut header = [0u8; TEA_BLOCK_SIZE * 2];
    let mut in_cipher = cipher;

    decrypt_round(&mut header[..8], &in_cipher[..8], &mut iv1, &mut iv2, key);
    in_cipher = &in_cipher[TEA_BLOCK_SIZE..];
    decrypt_round(&mut header[8..], &in_cipher[..8], &mut iv1, &mut iv2, key);
    in_cipher = &in_cipher[TEA_BLOCK_SIZE..];

    let hdr_skip_len = 1 + (header[0] & 7) as usize + FIXED_SALT_LEN;
    let real_plain_len = cipher.len() - hdr_skip_len - ZERO_PAD_LEN;
    let mut result = vec![0u8; real_plain_len];

    // 复制第一块明文
    let copy_len = std::cmp::min(header.len() - hdr_skip_len, real_plain_len);
    result[..copy_len].copy_from_slice(&header[hdr_skip_len..hdr_skip_len + copy_len]);

    if real_plain_len != copy_len {
        let mut p_output = copy_len;
        
        // 解密剩余块
        let remaining_blocks = (cipher.len() - TEA_BLOCK_SIZE * 3) / TEA_BLOCK_SIZE;
        for _ in 0..remaining_blocks {
            decrypt_round(&mut result[p_output..p_output + 8], &in_cipher[..8], &mut iv1, &mut iv2, key);
            in_cipher = &in_cipher[TEA_BLOCK_SIZE..];
            p_output += TEA_BLOCK_SIZE;
        }

        // 最后一块
        let mut last_block = [0u8; TEA_BLOCK_SIZE];
        decrypt_round(&mut last_block, &in_cipher[..8], &mut iv1, &mut iv2, key);
        if p_output < real_plain_len {
            result[p_output] = last_block[0];
        }
    }

    Some(result)
}
