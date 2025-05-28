use anyhow::{Context, Result};
use clap::{Arg, Command};
use rayon::prelude::*;
use shared_lib::{
    Blake3Calculator, DirectoryManager, FileScanner, Formatter, RsaVerifier, Sha256Calculator,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug)]
struct Config {
    directory: PathBuf,
    public_key: Option<PathBuf>,
    algorithm: String,
    extensions: Vec<String>,
    parallel: bool,
    verbose: bool,
    show_progress: bool,
    buffer_size: usize,
    strict: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("."),
            public_key: Some(PathBuf::from("./public_key.pem")),
            algorithm: "blake3".to_string(),
            extensions: vec!["tar.gz".to_string()],
            parallel: true,
            verbose: false,
            show_progress: false,
            buffer_size: 64 * 1024,
            strict: false,
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct VerificationResult {
    filename: String,
    file_exists: bool,
    hash_match: bool,
    signature_valid: bool,
    algorithm_used: String,
    expected_hash: String,
    actual_hash: String,
    file_size: u64,
    verification_time: f64,
    error_message: Option<String>,
}

fn main() -> Result<()> {
    let matches = Command::new("check-hash")
        .version("1.0.0")
        .author("LeeXN")
        .about("高性能文件哈希验证和数字签名验证工具 - 基于BLAKE3")
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIR")
                .help("要验证的目录路径")
                .default_value("."),
        )
        .arg(
            Arg::new("public-key")
                .short('k')
                .long("public-key")
                .value_name("FILE")
                .help("公钥文件路径")
                .default_value("./public_key.pem"),
        )
        .arg(
            Arg::new("algorithm")
                .short('a')
                .long("algorithm")
                .value_name("ALGO")
                .help("哈希算法 (blake3, sha256, auto)")
                .default_value("auto"),
        )
        .arg(
            Arg::new("extensions")
                .short('e')
                .long("extensions")
                .value_name("EXT")
                .help("文件扩展名 (逗号分隔)")
                .default_value("tar.gz"),
        )
        .arg(
            Arg::new("no-parallel")
                .long("no-parallel")
                .help("禁用并行处理")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("详细输出")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("buffer-size")
                .short('b')
                .long("buffer-size")
                .value_name("SIZE")
                .help("缓冲区大小 (字节)")
                .default_value("65536"),
        )
        .arg(
            Arg::new("no-verify")
                .long("no-verify")
                .help("不验证数字签名")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("strict")
                .long("strict")
                .help("严格模式：所有文件都必须通过验证")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("以JSON格式输出结果")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("progress")
                .long("progress")
                .help("在并行模式下显示进度（可能导致输出混乱）")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let config = Config {
        directory: PathBuf::from(matches.get_one::<String>("directory").unwrap()),
        public_key: if matches.get_flag("no-verify") {
            None
        } else {
            Some(PathBuf::from(matches.get_one::<String>("public-key").unwrap()))
        },
        algorithm: matches.get_one::<String>("algorithm").unwrap().to_string(),
        extensions: matches
            .get_one::<String>("extensions")
            .unwrap()
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
        parallel: !matches.get_flag("no-parallel"),
        verbose: matches.get_flag("verbose"),
        show_progress: matches.get_flag("progress"),
        buffer_size: matches
            .get_one::<String>("buffer-size")
            .unwrap()
            .parse()
            .context("Invalid buffer size")?,
        strict: matches.get_flag("strict"),
    };

    let json_output = matches.get_flag("json");

    if config.verbose && !json_output {
        println!("配置信息:");
        println!("  目录: {}", config.directory.display());
        println!("  算法: {}", config.algorithm);
        println!("  扩展名: {:?}", config.extensions);
        println!("  并行处理: {}", config.parallel);
        println!("  严格模式: {}", config.strict);
        println!("  缓冲区大小: {} bytes", config.buffer_size);
        if let Some(key_path) = &config.public_key {
            println!("  公钥: {}", key_path.display());
        } else {
            println!("  公钥: 不验证签名");
        }
        println!();
    }

    let results = run_hash_verification(config)?;
    
    if json_output {
        output_json(&results)?;
    } else {
        output_standard(&results)?;
    }

    // 检查是否有验证失败的文件
    let failed_count = results.iter().filter(|r| !r.hash_match || !r.signature_valid).count();
    
    if failed_count > 0 {
        if !json_output {
            eprintln!("\n验证失败: {} 个文件未通过验证", failed_count);
        }
        std::process::exit(1);
    }

    Ok(())
}

fn run_hash_verification(config: Config) -> Result<Vec<VerificationResult>> {
    let start_time = Instant::now();

    // 检查签名目录是否存在
    let signatures_dir = config.directory.join("signatures");
    if !signatures_dir.exists() {
        return Err(anyhow::anyhow!(
            "签名目录不存在: {}",
            signatures_dir.display()
        ));
    }

    // 扫描文件
    let scanner = FileScanner::new()
        .with_extensions(config.extensions.clone())
        .with_recursive(false);

    let files = scanner
        .scan_directory(&config.directory)
        .context("Failed to scan directory")?;

    if files.is_empty() {
        if config.verbose {
            println!("在目录 {} 中没有找到匹配的文件", config.directory.display());
        }
        return Ok(Vec::new());
    }

    if config.verbose {
        println!("找到 {} 个文件需要验证:", files.len());
        for file in &files {
            println!("  {}", file.display());
        }
        println!();
    }

    // 初始化验证器
    let verifier = if let Some(public_key_path) = &config.public_key {
        if public_key_path.exists() {
            Some(
                RsaVerifier::from_pem_file(public_key_path)
                    .context("Failed to load public key")?,
            )
        } else {
            if config.verbose {
                eprintln!("警告: 公钥文件不存在: {}, 不适用签名验证", public_key_path.display());
            }
            None
        }
    } else {
        None
    };

    // 验证文件
    let results = if config.parallel {
        verify_files_parallel(&files, &config, &signatures_dir, &verifier)?
    } else {
        verify_files_sequential(&files, &config, &signatures_dir, &verifier)?
    };

    let elapsed = start_time.elapsed();
    if config.verbose {
        let total_size: u64 = results.iter().map(|r| r.file_size).sum();
        println!();
        println!("验证完成!");
        println!("  文件数量: {}", results.len());
        println!("  总大小: {}", Formatter::format_file_size(total_size));
        println!("  耗时: {:.2}s", elapsed.as_secs_f64());
    }

    Ok(results)
}

fn verify_files_parallel(
    files: &[PathBuf],
    config: &Config,
    signatures_dir: &Path,
    verifier: &Option<RsaVerifier>,
) -> Result<Vec<VerificationResult>> {
    if config.verbose && !config.show_progress {
        println!("开始并行验证 {} 个文件...", files.len());
    }
    
    if config.show_progress {
        // 显示进度模式（可能输出混乱）
        files
            .par_iter()
            .enumerate()
            .map(|(index, file_path)| {
                verify_single_file(file_path, config, signatures_dir, verifier, index + 1, files.len())
            })
            .collect()
    } else {
        // 简单模式
        files
            .par_iter()
            .map(|file_path| {
                verify_single_file(file_path, config, signatures_dir, verifier, 0, 0)
            })
            .collect()
    }
}

fn verify_files_sequential(
    files: &[PathBuf],
    config: &Config,
    signatures_dir: &Path,
    verifier: &Option<RsaVerifier>,
) -> Result<Vec<VerificationResult>> {
    files
        .iter()
        .enumerate()
        .map(|(index, file_path)| {
            verify_single_file(file_path, config, signatures_dir, verifier, index + 1, files.len())
        })
        .collect()
}

fn verify_single_file(
    file_path: &Path,
    config: &Config,
    signatures_dir: &Path,
    verifier: &Option<RsaVerifier>,
    current: usize,
    total: usize,
) -> Result<VerificationResult> {
    let start_time = Instant::now();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    if config.verbose && total > 0 {
        println!(
            "{}",
            Formatter::format_progress(current, total, &filename)
        );
    } else if config.verbose {
        println!("验证文件: {}", filename);
    }

    let mut result = VerificationResult {
        filename: filename.clone(),
        file_exists: file_path.exists(),
        hash_match: false,
        signature_valid: false,
        algorithm_used: String::new(),
        expected_hash: String::new(),
        actual_hash: String::new(),
        file_size: 0,
        verification_time: 0.0,
        error_message: None,
    };

    if !result.file_exists {
        result.error_message = Some("文件不存在".to_string());
        result.verification_time = start_time.elapsed().as_secs_f64();
        return Ok(result);
    }

    result.file_size = file_path.metadata()?.len();

    // 确定使用的算法和读取期望的哈希值
    let (algorithm, expected_hash) = determine_algorithm_and_hash(config, signatures_dir, &filename)?;
    result.algorithm_used = algorithm.clone();
    result.expected_hash = expected_hash.clone();

    if expected_hash.is_empty() {
        result.error_message = Some("未找到哈希文件".to_string());
        result.verification_time = start_time.elapsed().as_secs_f64();
        return Ok(result);
    }

    // 计算实际哈希值
    let actual_hash = match algorithm.as_str() {
        "blake3" => {
            let calculator = Blake3Calculator::new().with_buffer_size(config.buffer_size);
            calculator.hash_file(file_path)?
        }
        "sha256" => {
            let calculator = Sha256Calculator::new().with_buffer_size(config.buffer_size);
            calculator.hash_file(file_path)?
        }
        _ => {
            result.error_message = Some(format!("不支持的算法: {}", algorithm));
            result.verification_time = start_time.elapsed().as_secs_f64();
            return Ok(result);
        }
    };

    result.actual_hash = actual_hash.clone();
    result.hash_match = expected_hash == actual_hash;

    // 验证数字签名
    if let Some(verifier) = verifier {
        let sig_file = DirectoryManager::get_signature_file_path(signatures_dir, &filename);
        if sig_file.exists() {
            match fs::read(&sig_file) {
                Ok(signature_bytes) => {
                    match verifier.verify_hash(&expected_hash, &signature_bytes) {
                        Ok(is_valid) => result.signature_valid = is_valid,
                        Err(e) => {
                            result.error_message = Some(format!("签名验证错误: {}", e));
                        }
                    }
                }
                Err(e) => {
                    result.error_message = Some(format!("读取签名文件失败: {}", e));
                }
            }
        } else {
            result.error_message = Some("签名文件不存在".to_string());
        }
    } else {
        result.signature_valid = true; // 如果不验证签名，则认为签名有效
    }

    result.verification_time = start_time.elapsed().as_secs_f64();
    Ok(result)
}

fn determine_algorithm_and_hash(
    config: &Config,
    signatures_dir: &Path,
    filename: &str,
) -> Result<(String, String)> {
    match config.algorithm.as_str() {
        "blake3" => {
            let hash_file = DirectoryManager::get_blake3_file_path(signatures_dir, filename);
            if hash_file.exists() {
                let hash = fs::read_to_string(&hash_file)
                    .with_context(|| format!("Failed to read BLAKE3 hash file: {}", hash_file.display()))?
                    .trim()
                    .to_string();
                Ok(("blake3".to_string(), hash))
            } else {
                Ok(("blake3".to_string(), String::new()))
            }
        }
        "sha256" => {
            let hash_file = DirectoryManager::get_hash_file_path(signatures_dir, filename);
            if hash_file.exists() {
                let hash = fs::read_to_string(&hash_file)
                    .with_context(|| format!("Failed to read SHA256 hash file: {}", hash_file.display()))?
                    .trim()
                    .to_string();
                Ok(("sha256".to_string(), hash))
            } else {
                Ok(("sha256".to_string(), String::new()))
            }
        }
        "auto" | _ => {
            // 优先尝试BLAKE3
            let blake3_file = DirectoryManager::get_blake3_file_path(signatures_dir, filename);
            if blake3_file.exists() {
                let hash = fs::read_to_string(&blake3_file)
                    .with_context(|| format!("Failed to read BLAKE3 hash file: {}", blake3_file.display()))?
                    .trim()
                    .to_string();
                return Ok(("blake3".to_string(), hash));
            }

            // 然后尝试SHA256
            let sha256_file = DirectoryManager::get_hash_file_path(signatures_dir, filename);
            if sha256_file.exists() {
                let hash = fs::read_to_string(&sha256_file)
                    .with_context(|| format!("Failed to read SHA256 hash file: {}", sha256_file.display()))?
                    .trim()
                    .to_string();
                return Ok(("sha256".to_string(), hash));
            }

            Ok(("unknown".to_string(), String::new()))
        }
    }
}

fn output_standard(results: &[VerificationResult]) -> Result<()> {
    println!("文件哈希验证结果:");
    println!("{:-<80}", "");

    let mut all_passed = true;

    for result in results {
        let status = if result.hash_match && result.signature_valid {
            "✓ 通过"
        } else {
            all_passed = false;
            "✗ 失败"
        };

        println!("文件: {} - {}", result.filename, status);
        
        if !result.file_exists {
            println!("  错误: 文件不存在");
            continue;
        }

        println!("  大小: {}", Formatter::format_file_size(result.file_size));
        println!("  算法: {}", result.algorithm_used);
        
        if !result.expected_hash.is_empty() {
            println!("  期望哈希: {}", result.expected_hash);
            println!("  实际哈希: {}", result.actual_hash);
            println!("  哈希匹配: {}", if result.hash_match { "是" } else { "否" });
        }
        
        println!("  签名验证: {}", if result.signature_valid { "通过" } else { "失败" });
        
        if let Some(error) = &result.error_message {
            println!("  错误信息: {}", error);
        }
        
        println!("{:-<80}", "");
    }

    if all_passed {
        println!("所有文件验证通过!");
    } else {
        println!("部分文件验证失败!");
    }

    Ok(())
}

fn output_json(results: &[VerificationResult]) -> Result<()> {
    let json_output = serde_json::to_string_pretty(results)
        .context("Failed to serialize results to JSON")?;
    println!("{}", json_output);
    Ok(())
}
