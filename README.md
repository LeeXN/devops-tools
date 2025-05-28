# Devops-Tools: 

Devops 工具集

目前已实现：
- 文件哈希生成工具 gen-hash
- 文件哈希验证工具 check-hash

用于给若干文件生成哈希值和签名，并验证文件的哈希值和签名确保文件未被篡改。


## 快速开始

```bash
# 编译项目
cargo build --release

# 简洁模式：快速处理文件
./target/release/gen-hash -d /path/to/files
# 输出: 处理 10 个文件...
#       ✓ 完成 (2.34s, 1250 MB/s)

# 详细模式：查看处理过程
./target/release/gen-hash -d /path/to/files -v

# 验证文件
./target/release/check-hash -d /path/to/files
```

## 特性

- 🚀 **高性能**: 基于 BLAKE3 算法，比 SHA-256 快数倍
- 🔒 **安全**: 支持 RSA 数字签名验证
- ⚡ **并行处理**: 利用多核 CPU 并行计算哈希值
- 🔄 **兼容性**: 输出格式兼容 `b3sum` 和 `sha256sum`
- 📊 **多格式输出**: 支持标准格式、JSON 格式输出
- 🛠️ **灵活配置**: 支持多种哈希算法和自定义参数
- 🎯 **用户友好**: 提供简洁、详细、调试三种输出模式
- 🔍 **智能诊断**: 详细的错误信息和性能统计

## 项目结构

```
rs-tools/
├── gen-hash/          # 哈希生成工具
├── check-hash/        # 哈希验证工具
├── shared-lib/        # 共享库
└── README.md
```

## 安装

### 从源码编译

```bash
# 克隆项目
git clone <repository-url>
cd rs-tools

# 编译所有工具
cargo build --release

# 编译后的二进制文件位于
# target/release/gen-hash
# target/release/check-hash
```

### 系统要求

- Rust 1.70+
- OpenSSL 开发库
- Linux/macOS/Windows

## 使用方法

### gen-hash - 哈希生成工具

用于计算文件哈希值并生成数字签名，替代原有的 shell 脚本。

#### 基本用法

```bash
# 简洁模式：在当前目录生成所有 .tar.gz 文件的 BLAKE3 哈希和签名
./target/release/gen-hash
# 输出: 处理 2 个文件...
#       ✓ 完成 (0.12s, 2056 MB/s)

# 详细模式：显示配置信息和处理进度
./target/release/gen-hash -v
# 输出: 配置信息:
#         目录: /path/to/files
#         算法: blake3
#       找到 2 个文件需要处理
#       开始处理...
#       [1/2] file1.tar.gz (247.62 MB)
#       [2/2] file2.tar.gz (6.20 MB)
#       处理完成!

# 调试模式：显示详细的性能和错误信息
./target/release/gen-hash --debug
# 输出: 配置信息:
#         目录: /path/to/files
#         算法: blake3
#         并行处理: true
#         缓冲区大小: 65536 bytes
#       [1/2] file1.tar.gz
#         大小: 247.62 MB, 权限: 644
#         哈希计算: 0.110s
#         文件写入: 0.003s

# 指定目录和私钥
./target/release/gen-hash -d /path/to/files -k /path/to/private.pem

# 使用 SHA256 算法
./target/release/gen-hash -a sha256

# 同时生成 BLAKE3 和 SHA256 哈希
./target/release/gen-hash -a both

# 输出 b3sum 兼容格式
./target/release/gen-hash -f b3sum

# 输出 JSON 格式
./target/release/gen-hash -f json

# 串行处理（显示实时进度）
./target/release/gen-hash --no-parallel -v
```

#### 参数说明

**基本参数**
- `-d, --directory <DIR>`: 要处理的目录路径 (默认: 当前目录)
- `-k, --private-key <FILE>`: 私钥文件路径 (默认: `./private_key.pem`)
- `-a, --algorithm <ALGO>`: 哈希算法 (blake3, sha256, both) (默认: blake3)
- `-e, --extensions <EXT>`: 文件扩展名，逗号分隔 (默认: tar.gz)

**输出控制**
- `-v, --verbose`: 详细输出（显示配置信息、处理进度和完整结果）
- `--debug`: 调试模式（显示性能统计、文件权限等详细信息）
- `-f, --format <FORMAT>`: 输出格式 (standard, json, b3sum, sha256sum) (默认: standard)

**性能选项**
- `--no-parallel`: 禁用并行处理（串行模式下显示实时进度）
- `-b, --buffer-size <SIZE>`: 缓冲区大小，字节 (默认: 65536)

**其他选项**
- `--no-sign`: 不生成数字签名

#### 输出模式

**简洁模式（默认）**
```
处理 2 个文件...
✓ 完成 (0.12s, 2056 MB/s)
```

**详细模式（-v）**
```
配置信息:
  目录: /path/to/files
  算法: blake3
  扩展名: ["tar.gz"]
  并行处理: true
  私钥: ./private_key.pem

找到 2 个文件需要处理
开始处理...
[1/2] file1.tar.gz (247.62 MB)
[2/2] file2.tar.gz (6.20 MB)

文件哈希生成结果:
--------------------------------------------------------------------------------
文件: file1.tar.gz
大小: 247.62 MB
BLAKE3: 3946499f8a0d78ca3ac14982085646249f5fd417b0723a9366dcd32e0db5e453
签名: 389403dd145a3fea...
处理时间: 0.113s
--------------------------------------------------------------------------------

处理完成!
  文件数量: 2
  总大小: 253.81 MB
  耗时: 0.12s
  吞吐量: 2056.28 MB/s
```

**调试模式（--debug）**
```
配置信息:
  目录: /path/to/files
  算法: blake3
  扩展名: ["tar.gz"]
  并行处理: true
  缓冲区大小: 65536 bytes
  私钥: ./private_key.pem

找到 2 个文件需要处理:
  /path/to/files/file1.tar.gz
  /path/to/files/file2.tar.gz

开始并行处理...
[详细的性能统计和错误诊断信息]
```

#### 输出文件

工具会在目标目录创建 `signatures/` 子目录，包含：

- `filename.tar.gz.b3`: BLAKE3 哈希文件
- `filename.tar.gz.hash`: SHA256 哈希文件  
- `filename.tar.gz.sig`: 数字签名文件

### check-hash - 哈希验证工具

用于验证文件哈希值和数字签名，替代原有的验证脚本。

#### 基本用法

```bash
# 验证当前目录的所有文件
./target/release/check-hash

# 指定目录和公钥
./target/release/check-hash -d /path/to/files -k /path/to/public.pem

# 自动检测算法
./target/release/check-hash -a auto

# 详细输出
./target/release/check-hash -v

# JSON 格式输出
./target/release/check-hash --json

# 严格模式（所有文件必须通过验证）
./target/release/check-hash --strict
```

#### 参数说明

**基本参数**
- `-d, --directory <DIR>`: 要验证的目录路径 (默认: 当前目录)
- `-k, --public-key <FILE>`: 公钥文件路径 (默认: `./public_key.pem`)
- `-a, --algorithm <ALGO>`: 哈希算法 (blake3, sha256, auto) (默认: auto)
- `-e, --extensions <EXT>`: 文件扩展名，逗号分隔 (默认: tar.gz)

**输出控制**
- `-v, --verbose`: 详细输出
- `--json`: JSON 格式输出

**验证选项**
- `--no-verify`: 不验证数字签名
- `--strict`: 严格模式（所有文件必须通过验证）

**性能选项**
- `--no-parallel`: 禁用并行处理
- `-b, --buffer-size <SIZE>`: 缓冲区大小，字节 (默认: 65536)

#### 退出码

- `0`: 所有文件验证通过
- `1`: 有文件验证失败


## 高级用法

### 不同使用场景

**快速批量处理（推荐）**
```bash
# 简洁模式，适合脚本和自动化
./gen-hash -d /path/to/files
# 输出: 处理 10 个文件...
#       ✓ 完成 (2.34s, 1250 MB/s)
```

**交互式使用**
```bash
# 详细模式，适合手动操作
./gen-hash -d /path/to/files -v
# 显示配置信息、处理进度和完整结果
```

**问题诊断**
```bash
# 调试模式，适合排查问题
./gen-hash -d /path/to/files --debug
# 显示详细的性能统计和错误诊断信息
```

### 批量处理

```bash
# 处理多个目录（简洁输出）
for dir in dir1 dir2 dir3; do
    echo "处理目录: $dir"
    ./gen-hash -d "$dir"
done

# 并行处理多个目录
echo -e "dir1\ndir2\ndir3" | xargs -P 3 -I {} ./gen-hash -d {}

# 详细模式批量处理
for dir in dir1 dir2 dir3; do
    ./gen-hash -d "$dir" -v
done
```

### 性能调优

```bash
# 增大缓冲区提高大文件处理性能
./gen-hash -b 1048576  # 1MB buffer

# 禁用并行处理（低内存环境或需要实时进度）
./gen-hash --no-parallel -v

# 仅生成哈希，不签名（提高速度）
./gen-hash --no-sign

# 调试性能问题
./gen-hash --debug --no-parallel  # 显示详细计时信息
```

## 开发

### 构建

```bash
# 开发构建
cargo build

# 发布构建
cargo build --release

# 运行测试
cargo test

# 运行特定模块测试
cargo test -p shared-lib
```

### 代码结构

- `shared-lib/`: 共享功能库
  - `hash.rs`: 哈希计算模块
  - `signature.rs`: 数字签名模块
  - `utils.rs`: 工具函数模块
- `gen-hash/`: 哈希生成工具
- `check-hash/`: 哈希验证工具

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request！