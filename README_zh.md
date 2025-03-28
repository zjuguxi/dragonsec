# DragonSec

<!-- BADGIE TIME -->

[![codecov](https://codecov.io/gh/zjuguxi/dragonsec/branch/main/graph/badge.svg)](https://codecov.io/gh/zjuguxi/dragonsec)
![Python 版本](https://img.shields.io/badge/python-3.9%2B-blue)
![许可证](https://img.shields.io/badge/license-Apache%202-green)

<!-- END BADGIE TIME -->

DragonSec 是一个结合传统静态分析和 AI 驱动的代码审查的高级安全扫描工具。

[English](./README.md)

## 特性

- **多 AI 模型支持**:
  - OpenAI GPT-4
  - Google Gemini
  - Deepseek (OpenRouter)
  - Grok
  - 本地 AI 模型 (Ollama)

- **静态分析**:
  - 集成 Semgrep 进行可靠的静态代码分析
  - 自定义安全规则和模式
  - 支持多种编程语言
  - 缓存机制提升性能

- **AI 驱动分析**:
  - 深度代码理解
  - 上下文感知的漏洞检测
  - 误报过滤
  - 安全评分系统

- **高级特性**:
  - 异步并行处理
  - 批量文件处理
  - 详细进度跟踪
  - 全面的输出报告

## 安装

```bash
pip install dragonsec
```

## 快速开始

1. 设置 API 密钥:
```bash
export OPENAI_API_KEY="your-openai-key"  # OpenAI 模型
export GEMINI_API_KEY="your-gemini-key"  # Google Gemini
export OPENROUTER_API_KEY="your-openrouter-key"  # Deepseek (OpenRouter)
```

2. 运行扫描:
```bash
# 使用 OpenAI GPT-4
dragonsec scan --path /path/to/code --mode openai --api-key $OPENAI_API_KEY

# 使用 Google Gemini
dragonsec scan --path /path/to/code --mode gemini --api-key $GEMINI_API_KEY

# 使用 Deepseek (OpenRouter)
dragonsec scan --path /path/to/code --mode deepseek --api-key $OPENROUTER_API_KEY

# 使用本地 AI 模型 (Ollama)
dragonsec scan --path /path/to/code --mode local --local-url http://localhost:11434 --local-model deepseek-r1:32b

# 仅使用 Semgrep (无需 API 密钥)
dragonsec scan --path /path/to/code --mode semgrep
```

## 配置

DragonSec 使用可自定义的默认配置:

```python
# 自定义配置
DEFAULT_CONFIG = {
    'skip_dirs': {'node_modules', 'build', 'dist', 'venv'},  # 跳过目录
    'test_dir_patterns': {'test', 'tests', 'spec', 'examples'},  # 测试目录模式
    'test_file_patterns': {'test_', '_test', 'spec_', '_spec'},  # 测试文件模式
    'batch_size': 4,  # 批处理大小
    'batch_delay': 0.1,  # 批处理延迟
    'output_dir': '~/.dragonsec/scan_results'  # 输出目录
}
```

您可以使用命令行选项覆盖这些设置:
- `--batch-size`: 并行处理的文件数量
- `--batch-delay`: 批处理之间的延迟（秒）
- `--include-tests`: 包含测试文件
- `--verbose`: 显示详细进度
- `--output-dir`: 自定义扫描结果目录
- `--local-url`: 本地 AI 模型服务器 URL
- `--local-model`: 本地提供者的模型名称

## 支持的语言

- Python
- JavaScript/TypeScript
- Java
- Go
- PHP
- C/C++
- C#
- Ruby
- Rust
- Swift
- Dockerfile

## 输出

结果以 JSON 格式保存，包含:
- 详细的漏洞描述
- 严重程度评级
- 行号和代码片段
- 风险分析
- 修复建议
- 整体安全评分
- 扫描元数据和统计信息

## 命令行使用

DragonSec 提供多个命令和选项:

### 主要命令

```bash
dragonsec scan   # 运行安全扫描
dragonsec rules  # 列出可用的安全规则
```

### 扫描命令选项

```bash
dragonsec scan [选项]

必需:
  --path PATH               要扫描的路径（文件或目录）

扫描模式:
  --mode MODE              扫描模式 [默认: semgrep]
                          选项:
                          - semgrep (基础静态分析)
                          - openai (OpenAI)
                          - gemini (Google Gemini)
                          - deepseek (Deepseek OpenRouter)
                          - local (本地 AI 模型)

认证:
  --api-key KEY            AI 服务的 API 密钥（AI 模式必需）

本地 AI 设置:
  --local-url URL         本地模型服务器 URL [默认: http://localhost:11434]
  --local-model MODEL     本地提供者的模型名称 [默认: deepseek-r1:32b]

性能:
  --batch-size N          每批处理的文件数量 [默认: 4]
  --batch-delay SECONDS   批处理之间的延迟 [默认: 0.1]

文件选择:
  --include-tests         包含测试文件 [默认: False]

输出:
  --output-dir DIR        扫描结果目录 [默认: ~/.dragonsec/scan_results]
  --verbose, -v          显示详细进度 [默认: False]
```

### 示例命令

```bash
# 使用默认设置的基本扫描
dragonsec scan --path ./myproject

# 使用 OpenAI 的 AI 增强扫描
dragonsec scan \
  --path ./myproject \
  --mode openai \
  --api-key $OPENAI_API_KEY \
  --batch-size 4 \
  --batch-delay 0.2 \
  --include-tests \
  --verbose

# 本地 AI 模型扫描
dragonsec scan \
  --path ./myproject \
  --mode local \
  --local-url http://localhost:11434 \
  --local-model deepseek-r1:32b

# 查看可用的安全规则
dragonsec rules
```
