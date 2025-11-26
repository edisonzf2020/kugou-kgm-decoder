use std::sync::LazyLock;

use clap::Parser;

pub fn get<'a>() -> &'a Config {
    static CFG: LazyLock<Config> = LazyLock::new(Config::parse);
    &CFG
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(clap::Parser, Default)]
#[command(version, about, after_help = after_help())]
pub struct Config {
    /// The target file or folder to be processed
    #[arg()]
    pub target: String,

    /// Processing files and directories recursively
    #[clap(short, long)]
    pub recursive: bool,

    /// Delete original file after decoding
    #[clap(short = 'd', long)]
    pub delete_file: bool,

    /// Path to KuGou key file for KGG decryption.
    /// Supports: .db (SQLCipher), .txt (key=value), .json ({"key": "value"})
    #[clap(long, value_name = "PATH")]
    pub kgg_db: Option<String>,
}

fn after_help() -> String {
    let author = std::env!["CARGO_PKG_AUTHORS"];
    let repository = std::env!["CARGO_PKG_REPOSITORY"];

    format!("author    : {author}\nrepository: {repository}")
}
