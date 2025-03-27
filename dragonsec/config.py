"""DragonSec configuration"""

from pathlib import Path
import os

# 基础配置
DEFAULT_CONFIG = {
    # 文件选择
    "skip_dirs": {
        "node_modules",
        "build",
        "dist",
        "venv",
        "__pycache__",
        ".git",
        ".svn",
        ".hg",
        "htmlcov",
    },
    "test_dir_patterns": {"tests", "test", "__tests__", "__test__"},
    "test_file_patterns": {"test_", "_test", "tests.", ".test.", "spec.", ".spec."},
    "supported_extensions": {"py", "js", "ts", "java", "go", "php"},
    # 性能配置
    "batch_size": 4,
    "batch_delay": 0.1,
    # 路径配置
    "output_dir": str(Path.home() / ".dragonsec" / "scan_results"),
    "rules_dir": str(Path.home() / ".dragonsec" / "rules"),
    # 日志配置
    "log_level": "INFO",
    "log_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
}

# Add debug logging configuration
LOG_LEVEL = os.getenv("DRAGONSEC_LOG_LEVEL", "INFO")
