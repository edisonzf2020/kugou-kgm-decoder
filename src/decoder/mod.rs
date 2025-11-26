//! 音频解码器模块
//!
//! 支持的格式：
//! - KGM/KGMA：酷狗音乐加密格式
//! - KGG：酷狗新版加密格式（需要数据库密钥）
//! - NCM：网易云音乐加密格式

mod crypto;
mod kgg;
mod kugou;
mod ncm;

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use kgg::Kgg;
use kugou::KuGou;
use ncm::Ncm;

pub use kgg::{auto_load_key_map, load_key_map_from_db, KeyMap};

/// 解码器 trait
pub trait Decoder<'a>: Sized + Read {
    #[allow(dead_code)]
    fn new(origin: impl Read + 'a) -> Self;
    fn try_new(origin: impl Read + 'a) -> Option<Self>;
    #[allow(dead_code)]
    fn decodeable_length_interval() -> (u64, u64);
}

/// 解码器类型枚举，用于支持多种格式
pub enum DecoderType {
    KuGou(KuGou<'static>),
    Ncm(Ncm<'static>),
    Kgg(Kgg<'static>),
}

impl Read for DecoderType {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DecoderType::KuGou(d) => d.read(buf),
            DecoderType::Ncm(d) => d.read(buf),
            DecoderType::Kgg(d) => d.read(buf),
        }
    }
}

/// 检测文件格式
fn detect_format(path: &Path) -> Option<&'static str> {
    let mut file = File::open(path).ok()?;
    let mut header = [0u8; 28];
    file.read_exact(&mut header).ok()?;

    // 检查酷狗 KGM 格式魔数
    const KGM_MAGIC: [u8; 28] = [
        0x7c, 0xd5, 0x32, 0xeb, 0x86, 0x02, 0x7f, 0x4b, 0xa8, 0xaf, 0xa6, 0x8e, 0x0f, 0xff, 0x99,
        0x14, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    if header == KGM_MAGIC {
        return Some("kgm");
    }

    // 检查 NCM 格式魔数
    if &header[..8] == b"CTENFDAM" {
        return Some("ncm");
    }

    // 检查 KGG 格式（通过扩展名判断，因为 KGG 没有明确的魔数）
    if let Some(ext) = path.extension() {
        if ext.to_string_lossy().to_lowercase() == "kgg" {
            return Some("kgg");
        }
    }

    None
}

/// 尝试创建解码器，自动识别文件格式（不支持 KGG）
#[allow(dead_code)]
pub fn new_from_file(path: &Path) -> Option<DecoderType> {
    let format = detect_format(path)?;

    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    match format {
        "kgm" => {
            let decoder = KuGou::try_new(reader)?;
            Some(DecoderType::KuGou(decoder))
        }
        "ncm" => {
            let decoder = Ncm::try_new(reader)?;
            Some(DecoderType::Ncm(decoder))
        }
        "kgg" => {
            // KGG 需要密钥映射，返回 None
            // 使用 new_from_file_with_keymap 代替
            None
        }
        _ => None,
    }
}

/// 尝试创建解码器，支持 KGG 格式（需要密钥映射）
pub fn new_from_file_with_keymap(path: &Path, key_map: Option<&KeyMap>) -> Option<DecoderType> {
    let format = detect_format(path)?;

    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    match format {
        "kgm" => {
            let decoder = KuGou::try_new(reader)?;
            Some(DecoderType::KuGou(decoder))
        }
        "ncm" => {
            let decoder = Ncm::try_new(reader)?;
            Some(DecoderType::Ncm(decoder))
        }
        "kgg" => {
            let key_map = key_map?;
            let decoder = Kgg::try_new_with_keymap(reader, key_map)?;
            Some(DecoderType::Kgg(decoder))
        }
        _ => None,
    }
}

/// 从 Read 创建解码器（仅支持酷狗格式，保持向后兼容）
#[allow(dead_code)]
pub fn new<'a>(data: impl Read + 'a) -> Option<impl Decoder<'a>> {
    KuGou::try_new(data)
}
