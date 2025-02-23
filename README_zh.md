# DragonSec

<!-- BADGIE TIME -->

[![codecov](https://codecov.io/gh/zjuguxi/dragonsec/branch/main/graph/badge.svg)](https://codecov.io/gh/zjuguxi/dragonsec)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-Apache%202-green)  

<!-- END BADGIE TIME -->

DragonSec 是一个先进的安全扫描工具，结合了传统静态分析和 AI 驱动的代码审查能力。

[English](./README.md)

## 特性

- **多 AI 模型支持**:
  - OpenAI GPT-4o
  - Google Gemini-1.5-flash
  - Deepseek R1 (阿里云)
  - xAI Grok
  - 更多模型即将支持...

- **静态分析**:
  - 集成 Semgrep 进行可靠的静态代码分析
  - 自定义安全规则和模式
  - 支持多种编程语言

- **混合分析**:
  - 结合 AI 洞察和静态分析结果
  - 通过交叉验证减少误报
  - 提供全面的安全评分
  - 异步并行处理

## 安装

```bash
pip install dragonsec
```

## 快速开始

1. 设置 API 密钥:
```bash
export OPENAI_API_KEY="your-openai-key"  # 用于 GPT-4
export GEMINI_API_KEY="your-gemini-key"  # 用于 Gemini
export DEEPSEEK_API_KEY="your-deepseek-key"  # 用于 Deepseek
```

2. 运行扫描:
```bash
# 使用 OpenAI GPT-4
dragonsec scan --path /path/to/code --mode openai --api-key $OPENAI_API_KEY

# 使用 Google Gemini-1.5-flash
dragonsec scan --path /path/to/code --mode gemini --api-key $GEMINI_API_KEY

# 使用 Deepseek R1 (阿里云)
dragonsec scan --path /path/to/code --mode deepseek --api-key $DEEPSEEK_API_KEY

# 仅使用 Semgrep (无需 API 密钥)
dragonsec scan --path /path/to/code --mode semgrep
```

## 配置

DragonSec 使用可自定义的默认配置:

```python
# 自定义配置
DEFAULT_CONFIG = {
    'skip_dirs': {'node_modules', 'build', ...},
    'batch_size': 4,
    'batch_delay': 0.1,
    ...
}
```

你可以通过命令行选项覆盖这些设置:
- `--batch-size`: 并行处理的文件数量
- `--batch-delay`: 批次间延迟(秒)
- `--include-tests`: 包含测试文件
- `--verbose`: 显示详细进度
- `--output-dir`: 扫描结果的自定义目录

## 支持的语言

- Python
- JavaScript
- Java
- Go
- PHP
- Dockerfile

## 输出

结果以 JSON 格式保存，包含:
- 详细的漏洞描述
- 严重性评级
- 行号
- 风险分析
- 修复建议
- 整体安全评分

## 命令行用法

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
  --path PATH               要扫描的路径(文件或目录)

扫描模式:
  --mode MODE              扫描模式 [默认: semgrep]
                          选项: 
                          - semgrep (基础静态分析)
                          - openai (GPT-4o 增强)
                          - gemini (Gemini-1.5-flash 增强)
                          - deepseek (Deepseek R1 增强)

认证:
  --api-key KEY            AI 服务的 API 密钥(AI 模式必需)

性能:
  --batch-size N          每批处理的文件数 [默认: 4]
  --batch-delay SECONDS   批次间延迟 [默认: 0.1]

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

# AI 增强扫描
dragonsec scan \
  --path ./myproject \
  --mode openai \
  --api-key $OPENAI_API_KEY \
  --batch-size 4 \
  --batch-delay 0.2 \
  --include-tests \
  --verbose

# 查看可用的安全规则
dragonsec rules
```
