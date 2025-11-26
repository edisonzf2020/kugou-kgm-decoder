//! 酷狗 KGG 格式解码器
//!
//! KGG 是酷狗较新的加密格式，使用 QMC2 算法加密
//! 需要从酷狗数据库中获取解密密钥

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::crypto::qmc2::{self, Qmc2Decryptor};
use super::Decoder;

/// 密钥映射表：audio_hash -> ekey
pub type KeyMap = HashMap<String, String>;

/// 获取跨平台的默认酷狗数据库路径
pub fn get_default_db_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // Windows: %APPDATA%\KuGou8\KGMusicV3.db
        if let Some(appdata) = std::env::var_os("APPDATA") {
            let mut path = PathBuf::from(appdata);
            path.push("KuGou8");
            path.push("KGMusicV3.db");
            paths.push(path);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: ~/Library/Containers/com.kugou.mac.Music/Data/Library/Application Support/
        if let Some(home) = std::env::var_os("HOME") {
            let mut path = PathBuf::from(&home);
            path.push("Library/Containers/com.kugou.mac.Music/Data/Library/Application Support/KGMusicV3.db");
            paths.push(path);
            
            // 备选路径
            let mut path2 = PathBuf::from(&home);
            path2.push("Library/Application Support/KuGou/KGMusicV3.db");
            paths.push(path2);
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linux: ~/.config/KuGou/ 或 ~/.kugou/
        if let Some(home) = std::env::var_os("HOME") {
            let mut path = PathBuf::from(&home);
            path.push(".config/KuGou/KGMusicV3.db");
            paths.push(path);
            
            let mut path2 = PathBuf::from(&home);
            path2.push(".kugou/KGMusicV3.db");
            paths.push(path2);
        }
    }

    paths
}

/// 自动查找并加载酷狗数据库
pub fn auto_load_key_map() -> Result<KeyMap, String> {
    let paths = get_default_db_paths();
    
    for path in &paths {
        if path.exists() {
            match load_key_map_from_db(path) {
                Ok(map) => {
                    println!("Found KGG database: {}", path.display());
                    return Ok(map);
                }
                Err(e) => {
                    println!("Warning: Failed to load {}: {}", path.display(), e);
                }
            }
        }
    }
    
    Err(format!(
        "未找到酷狗数据库，请使用 --kgg-db 参数指定路径。\n已搜索的路径:\n{}",
        paths.iter().map(|p| format!("  - {}", p.display())).collect::<Vec<_>>().join("\n")
    ))
}

/// 酷狗数据库 SQLCipher 密钥
#[allow(dead_code)]
const KG_DB_KEY: &str = "7777B48756BA491BB4CEE771A3E2727E";

/// 从密钥文件加载密钥映射
/// 
/// 支持两种格式：
/// 1. 简单文本格式：每行一个 "key_id=ekey" 对
/// 2. JSON 格式：{"key_id": "ekey", ...}
pub fn load_key_map_from_file(key_file_path: &Path) -> Result<KeyMap, String> {
    let content = std::fs::read_to_string(key_file_path)
        .map_err(|e| format!("无法读取密钥文件: {}", e))?;

    let content = content.trim();

    // 尝试 JSON 格式
    if content.starts_with('{') {
        return parse_json_key_map(content);
    }

    // 简单文本格式
    let mut key_map = KeyMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key_id, ekey)) = line.split_once('=') {
            key_map.insert(key_id.trim().to_string(), ekey.trim().to_string());
        }
    }

    if key_map.is_empty() {
        return Err("密钥文件为空或格式不正确".to_string());
    }

    Ok(key_map)
}

/// 解析 JSON 格式的密钥映射
fn parse_json_key_map(content: &str) -> Result<KeyMap, String> {
    // 简单的 JSON 解析，不依赖外部库
    let mut key_map = KeyMap::new();
    let content = content.trim_start_matches('{').trim_end_matches('}');

    for pair in content.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        // 解析 "key": "value" 格式
        let parts: Vec<&str> = pair.splitn(2, ':').collect();
        if parts.len() == 2 {
            let key_id = parts[0].trim().trim_matches('"').to_string();
            let ekey = parts[1].trim().trim_matches('"').to_string();
            if !key_id.is_empty() && !ekey.is_empty() {
                key_map.insert(key_id, ekey);
            }
        }
    }

    if key_map.is_empty() {
        return Err("JSON 密钥文件为空或格式不正确".to_string());
    }

    Ok(key_map)
}

/// 从酷狗数据库加载密钥映射（使用 SQLCipher）
/// 
/// 注意：由于酷狗使用自定义的 SQLCipher 配置，标准 SQLCipher 可能无法解密。
/// 建议使用 kgg-dec-mirror 工具导出密钥后，使用 load_key_map_from_file 加载。
pub fn load_key_map_from_db(db_path: &Path) -> Result<KeyMap, String> {
    // 首先检查是否是密钥文件（.txt 或 .json）
    if let Some(ext) = db_path.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        if ext == "txt" || ext == "json" {
            return load_key_map_from_file(db_path);
        }
    }

    use rusqlite::{Connection, OpenFlags};

    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("无法打开数据库: {}", e))?;

    // 尝试设置 SQLCipher 密钥
    let _ = conn.execute_batch(&format!("PRAGMA key = '{}';", KG_DB_KEY));

    // 查询密钥
    let mut stmt = conn
        .prepare(
            "SELECT EncryptionKeyId, EncryptionKey FROM ShareFileItems \
             WHERE EncryptionKey IS NOT NULL AND EncryptionKey != ''",
        )
        .map_err(|e| format!("SQL 准备失败: {}", e))?;

    let mut key_map = KeyMap::new();
    let rows = stmt
        .query_map([], |row| {
            let key_id: String = row.get(0)?;
            let key: String = row.get(1)?;
            Ok((key_id, key))
        })
        .map_err(|e| format!("查询失败: {}", e))?;

    for row in rows {
        if let Ok((key_id, key)) = row {
            key_map.insert(key_id, key);
        }
    }

    Ok(key_map)
}



/// KGG 解码器
pub struct Kgg<'a> {
    origin: Box<dyn Read + 'a>,
    decryptor: Box<dyn Qmc2Decryptor>,
    pos: usize,
}

impl<'a> Kgg<'a> {
    /// 使用密钥映射创建解码器
    pub fn try_new_with_keymap(mut origin: impl Read + 'a, key_map: &KeyMap) -> Option<Self> {
        // 读取文件头
        let mut header = [0u8; 1024];
        origin.read_exact(&mut header).ok()?;
        
        // 获取头部长度
        let header_len = u32::from_le_bytes(header[16..20].try_into().ok()?) as usize;
        
        // 检查版本（mode == 5）
        let mode = u32::from_le_bytes(header[20..24].try_into().ok()?);
        if mode != 5 {
            return None;
        }
        
        // 读取音频哈希长度和哈希值
        let audio_hash_len = u32::from_le_bytes(header[68..72].try_into().ok()?) as usize;
        if 72 + audio_hash_len > header.len() {
            return None;
        }
        let audio_hash = String::from_utf8_lossy(&header[72..72 + audio_hash_len]).to_string();
        
        // 查找密钥
        let ekey = key_map.get(&audio_hash)?;
        
        // 创建 QMC2 解密器
        let decryptor = qmc2::create_decryptor(ekey)?;
        
        // 跳过剩余头部
        if header_len > 1024 {
            let mut skip = vec![0u8; header_len - 1024];
            origin.read_exact(&mut skip).ok()?;
        }
        
        Some(Kgg {
            origin: Box::new(origin),
            decryptor,
            pos: 0,
        })
    }
}

impl<'a> Decoder<'a> for Kgg<'a> {
    fn new(_origin: impl Read + 'a) -> Self {
        panic!("KGG 解码器需要密钥映射，请使用 try_new_with_keymap")
    }

    fn try_new(_origin: impl Read + 'a) -> Option<Self> {
        // KGG 需要密钥映射，无法直接创建
        None
    }

    fn decodeable_length_interval() -> (u64, u64) {
        (0, u64::MAX)
    }
}

impl Read for Kgg<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.origin.read(buf)?;
        
        if len > 0 {
            self.decryptor.decrypt(&mut buf[..len], self.pos);
            self.pos += len;
        }
        
        Ok(len)
    }
}

/// 检测是否为 KGG 格式
#[allow(dead_code)]
pub fn is_kgg_format(header: &[u8]) -> bool {
    if header.len() < 24 {
        return false;
    }
    
    // KGG 文件头特征：偏移 20 处的 mode 值为 5
    // 这是一个简化的检测，实际可能需要更多验证
    let mode = u32::from_le_bytes(header[20..24].try_into().unwrap_or([0; 4]));
    mode == 5
}
