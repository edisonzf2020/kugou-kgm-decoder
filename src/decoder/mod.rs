//! 音频解码器模块
//! 
//! 支持的格式：
//! - KGM/KGMA：酷狗音乐加密格式
//! - NCM：网易云音乐加密格式

mod kugou;
mod ncm;

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use kugou::KuGou;
use ncm::Ncm;

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
}

impl Read for DecoderType {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DecoderType::KuGou(d) => d.read(buf),
            DecoderType::Ncm(d) => d.read(buf),
        }
    }
}

/// 检测文件格式
fn detect_format(path: &Path) -> Option<&'static str> {
    let mut file = File::open(path).ok()?;
    let mut header = [0u8; 28];
    file.read_exact(&mut header).ok()?;

    // 检查酷狗格式魔数
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

    None
}

/// 尝试创建解码器，自动识别文件格式
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
        _ => None,
    }
}

/// 从 Read 创建解码器（仅支持酷狗格式，保持向后兼容）
#[allow(dead_code)]
pub fn new<'a>(data: impl Read + 'a) -> Option<impl Decoder<'a>> {
    KuGou::try_new(data)
}
