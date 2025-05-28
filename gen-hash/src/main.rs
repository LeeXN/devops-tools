use anyhow::{Context, Result};
use clap::{Arg, Command};
use rayon::prelude::*;
use shared_lib::{
    Blake3Calculator, DirectoryManager, FileScanner, Formatter, RsaSigner, Sha256Calculator,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug)]
struct Config {
    directory: PathBuf,
    private_key: Option<PathBuf>,
    algorithm: String,
    extensions: Vec<String>,
    output_format: String,
    parallel: bool,
    verbose: bool,
    debug: bool,
    no_sign: bool,
    buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("."),
            private_key: Some(PathBuf::from("./private_key.pem")),
            algorithm: "blake3".to_string(),
            extensions: vec!["tar.gz".to_string()],
            output_format: "standard".to_string(),
            parallel: true,
            verbose: false,
            debug: false,
            no_sign: false,
            buffer_size: 64 * 1024,
        }
    }
}

fn main() -> Result<()> {
    let matches = Command::new("gen-hash")
        .version("1.0.0")
        .author("LeeXN")
        .about("高性能文件哈希生成和数字签名工具 - 基于BLAKE3")
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIR")
                .help("要处理的目录路径")
                .default_value("."),
        )
        .arg(
            Arg::new("private-key")
                .short('k')
                .long("private-key")
                .value_name("FILE")
                .help("私钥文件路径")
                .default_value("./private_key.pem"),
        )
        .arg(
            Arg::new("algorithm")
                .short('a')
                .long("algorithm")
                .value_name("ALGO")
                .help("哈希算法 (blake3, sha256, both)")
                .default_value("blake3"),
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
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("输出格式 (standard, json, b3sum, sha256sum)")
                .default_value("standard"),
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
            Arg::new("no-sign")
                .long("no-sign")
                .help("不生成数字签名")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("显示详细的调试信息（文件权限、大小等）")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let config = Config {
        directory: PathBuf::from(matches.get_one::<String>("directory").unwrap()),
        private_key: if matches.get_flag("no-sign") {
            None
        } else {
            Some(PathBuf::from(matches.get_one::<String>("private-key").unwrap()))
        },
        algorithm: matches.get_one::<String>("algorithm").unwrap().to_string(),
        extensions: matches
            .get_one::<String>("extensions")
            .unwrap()
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
        output_format: matches.get_one::<String>("format").unwrap().to_string(),
        parallel: !matches.get_flag("no-parallel"),
        verbose: matches.get_flag("verbose"),
        debug: matches.get_flag("debug"),
        no_sign: matches.get_flag("no-sign"),
        buffer_size: matches
            .get_one::<String>("buffer-size")
            .unwrap()
            .parse()
            .context("Invalid buffer size")?,
    };

    // 只在调试模式下显示详细配置信息
    if config.verbose {
        println!("配置信息:");
        println!("  目录: {}", config.directory.display());
        println!("  算法: {}", config.algorithm);
        println!("  扩展名: {:?}", config.extensions);
        println!("  并行处理: {}", config.parallel);
        println!("  缓冲区大小: {} bytes", config.buffer_size);
        if let Some(key_path) = &config.private_key {
            println!("  私钥: {}", key_path.display());
        } else {
            println!("  私钥: 不使用签名");
        }
        println!();
    }

    run_hash_generation(config)
}

fn run_hash_generation(config: Config) -> Result<()> {
    let start_time = Instant::now();

    // 扫描文件
    let scanner = FileScanner::new()
        .with_extensions(config.extensions.clone())
        .with_recursive(false);

    let files = scanner
        .scan_directory(&config.directory)
        .context("Failed to scan directory")?;

    if files.is_empty() {
        if config.verbose || config.debug {
            println!("在目录 {} 中没有找到匹配的文件", config.directory.display());
        }
        return Ok(());
    }

    // 根据不同模式显示不同的信息
    if config.debug {
        println!("找到 {} 个文件需要处理:", files.len());
        for file in &files {
            println!("  {}", file.display());
        }
        println!();
    } else if config.verbose {
        println!("找到 {} 个文件需要处理", files.len());
    } else {
        println!("处理 {} 个文件...", files.len());
    }

    // 创建签名目录
    let signatures_dir = DirectoryManager::create_signatures_dir(&config.directory)
        .with_context(|| format!("创建signatures目录失败: {} (可能是目录写入权限问题)", config.directory.display()))?;

    // 初始化签名器
    let signer = if let Some(private_key_path) = &config.private_key {
        if private_key_path.exists() {
            Some(
                RsaSigner::from_pem_file(private_key_path)
                    .context("Failed to load private key")?,
            )
        } else {
            if config.no_sign {
                None
            } else {
                return Err(anyhow::anyhow!("私钥文件不存在: {}, 请使用-k/--private-key指定私钥文件, 或使用--no-sign禁用签名", private_key_path.display()));
            }
        }
    } else {
        None
    };

    // 处理文件
    let results = if config.parallel {
        process_files_parallel(&files, &config, &signatures_dir, &signer)?
    } else {
        process_files_sequential(&files, &config, &signatures_dir, &signer)?
    };

    let elapsed = start_time.elapsed();
    let total_size: u64 = results.iter().map(|r| r.file_size).sum();

    // 根据不同模式显示不同的结果
    if config.verbose || config.debug {
        // 详细模式：显示完整结果
        output_results(&results, &config)?;
        
        println!();
        println!("处理完成!");
        println!("  文件数量: {}", results.len());
        println!("  总大小: {}", Formatter::format_file_size(total_size));
        println!("  耗时: {:.2}s", elapsed.as_secs_f64());
        if total_size > 0 {
            let throughput = total_size as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;
            println!("  吞吐量: {:.2} MB/s", throughput);
        }
    } else {
        // 简洁模式：只显示简单的完成信息
        if total_size > 0 {
            let throughput = total_size as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;
            println!("✓ 完成 ({:.2}s, {:.0} MB/s)", elapsed.as_secs_f64(), throughput);
        } else {
            println!("✓ 完成 ({:.2}s)", elapsed.as_secs_f64());
        }
    }

    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct FileResult {
    filename: String,
    blake3_hash: String,
    sha256_hash: String,
    file_size: u64,
    signature: Option<String>,
    processing_time: f64,
}

fn process_files_parallel(
    files: &[PathBuf],
    config: &Config,
    signatures_dir: &Path,
    signer: &Option<RsaSigner>,
) -> Result<Vec<FileResult>> {
    if config.debug {
        println!("开始并行处理...");
    } else if config.verbose {
        println!("开始处理...");
    }
    
    // 并行模式下不显示实时进度，避免输出混乱
    files
        .par_iter()
        .map(|file_path| {
            process_single_file(file_path, config, signatures_dir, signer, 0, 0)
        })
        .collect()
}

fn process_files_sequential(
    files: &[PathBuf],
    config: &Config,
    signatures_dir: &Path,
    signer: &Option<RsaSigner>,
) -> Result<Vec<FileResult>> {
    files
        .iter()
        .enumerate()
        .map(|(index, file_path)| {
            process_single_file(file_path, config, signatures_dir, signer, index + 1, files.len())
        })
        .collect()
}

fn process_single_file(
    file_path: &Path,
    config: &Config,
    signatures_dir: &Path,
    signer: &Option<RsaSigner>,
    current: usize,
    total: usize,
) -> Result<FileResult> {
    let start_time = Instant::now();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    // 获取文件大小和权限信息
    let metadata = file_path.metadata()
        .with_context(|| format!("无法获取文件元数据: {} (可能是权限问题)", file_path.display()))?;
    
    let file_size = metadata.len();
    
    // 只在串行模式下显示处理信息，避免并发输出混乱
    if !config.parallel {
        if config.debug && total > 0 {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                println!("[{}/{}] {}", current, total, filename);
                println!("  大小: {}, 权限: {:o}", Formatter::format_file_size(file_size), mode & 0o777);
            }
            #[cfg(not(unix))]
            {
                println!("[{}/{}] {}", current, total, filename);
                println!("  大小: {}", Formatter::format_file_size(file_size));
            }
        } else if config.verbose && total > 0 {
            println!("[{}/{}] {} ({})", current, total, filename, Formatter::format_file_size(file_size));
        }
    }

    // 计算哈希值
    let hash_start = if config.debug { Some(Instant::now()) } else { None };
    
    let (blake3_hash, sha256_hash) = match config.algorithm.as_str() {
        "blake3" => {
            let calculator = Blake3Calculator::new().with_buffer_size(config.buffer_size);
            let hash = calculator.hash_file(file_path)
                .with_context(|| format!("计算BLAKE3哈希失败: {} (可能是文件读取权限问题)", file_path.display()))?;
            (hash, String::new())
        }
        "sha256" => {
            let calculator = Sha256Calculator::new().with_buffer_size(config.buffer_size);
            let hash = calculator.hash_file(file_path)
                .with_context(|| format!("计算SHA256哈希失败: {} (可能是文件读取权限问题)", file_path.display()))?;
            (String::new(), hash)
        }
        "both" => {
            let blake3_calc = Blake3Calculator::new().with_buffer_size(config.buffer_size);
            let sha256_calc = Sha256Calculator::new().with_buffer_size(config.buffer_size);
            let blake3_hash = blake3_calc.hash_file(file_path)
                .with_context(|| format!("计算BLAKE3哈希失败: {} (可能是文件读取权限问题)", file_path.display()))?;
            let sha256_hash = sha256_calc.hash_file(file_path)
                .with_context(|| format!("计算SHA256哈希失败: {} (可能是文件读取权限问题)", file_path.display()))?;
            (blake3_hash, sha256_hash)
        }
        _ => return Err(anyhow::anyhow!("Unsupported algorithm: {}", config.algorithm)),
    };

    // 调试模式下显示哈希计算时间
    if let Some(hash_start_time) = hash_start {
        let hash_duration = hash_start_time.elapsed();
        if config.debug && !config.parallel {
            println!("  哈希计算: {:.3}s", hash_duration.as_secs_f64());
        }
    }

    // 保存哈希文件
    let write_start = if config.debug { Some(Instant::now()) } else { None };
    if !blake3_hash.is_empty() {
        let hash_file = DirectoryManager::get_blake3_file_path(signatures_dir, &filename);
        fs::write(&hash_file, &blake3_hash)
            .with_context(|| format!("写入BLAKE3哈希文件失败: {} (可能是目录写入权限问题)", hash_file.display()))?;
    }

    if !sha256_hash.is_empty() {
        let hash_file = DirectoryManager::get_hash_file_path(signatures_dir, &filename);
        fs::write(&hash_file, &sha256_hash)
            .with_context(|| format!("写入SHA256哈希文件失败: {} (可能是目录写入权限问题)", hash_file.display()))?;
    }

    // 调试模式下显示文件写入时间
    if let Some(write_start_time) = write_start {
        let write_duration = write_start_time.elapsed();
        if config.debug && !config.parallel {
            println!("  文件写入: {:.3}s", write_duration.as_secs_f64());
        }
    }

    // 生成数字签名
    let signature = if let Some(signer) = signer {
        let hash_to_sign = if !blake3_hash.is_empty() {
            &blake3_hash
        } else {
            &sha256_hash
        };

        if !hash_to_sign.is_empty() {
            let sig_bytes = signer.sign_hash(hash_to_sign)?;
            let sig_file = DirectoryManager::get_signature_file_path(signatures_dir, &filename);
            fs::write(&sig_file, &sig_bytes).with_context(|| {
                format!("Failed to write signature file: {}", sig_file.display())
            })?;
            Some(hex::encode(sig_bytes))
        } else {
            None
        }
    } else {
        None
    };

    let processing_time = start_time.elapsed().as_secs_f64();

    Ok(FileResult {
        filename,
        blake3_hash,
        sha256_hash,
        file_size,
        signature,
        processing_time,
    })
}

fn output_results(results: &[FileResult], config: &Config) -> Result<()> {
    match config.output_format.as_str() {
        "json" => output_json(results)?,
        "b3sum" => output_b3sum_format(results)?,
        "sha256sum" => output_sha256sum_format(results)?,
        "standard" | _ => output_standard_format(results, config)?,
    }
    Ok(())
}

fn output_standard_format(results: &[FileResult], config: &Config) -> Result<()> {
    println!("文件哈希生成结果:");
    println!("{:-<80}", "");

    for result in results {
        println!("文件: {}", result.filename);
        println!("大小: {}", Formatter::format_file_size(result.file_size));

        if !result.blake3_hash.is_empty() {
            println!("BLAKE3: {}", result.blake3_hash);
        }

        if !result.sha256_hash.is_empty() {
            println!("SHA256: {}", result.sha256_hash);
        }

        if let Some(signature) = &result.signature {
            println!("签名: {}...", &signature[..16]);
        }

        if config.verbose {
            println!("处理时间: {:.3}s", result.processing_time);
        }

        println!("{:-<80}", "");
    }

    Ok(())
}

fn output_b3sum_format(results: &[FileResult]) -> Result<()> {
    for result in results {
        if !result.blake3_hash.is_empty() {
            println!("{}  {}", result.blake3_hash, result.filename);
        }
    }
    Ok(())
}

fn output_sha256sum_format(results: &[FileResult]) -> Result<()> {
    for result in results {
        if !result.sha256_hash.is_empty() {
            println!("{}  {}", result.sha256_hash, result.filename);
        }
    }
    Ok(())
}

fn output_json(results: &[FileResult]) -> Result<()> {
    let json_output = serde_json::to_string_pretty(results)
        .context("Failed to serialize results to JSON")?;
    println!("{}", json_output);
    Ok(())
}
