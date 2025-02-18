import pytest
import asyncio
from dragonsec.core.scanner import SecurityScanner, ScanMode
from pathlib import Path
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.mark.asyncio
async def test_deepseek_performance():
    """Test Deepseek scanning performance"""
    # 创建测试文件
    test_dir = Path(__file__).parent / "test_files"
    test_dir.mkdir(exist_ok=True)
    
    # 创建一些测试文件
    test_files = [
        ("sql_injection.py", """
def unsafe_query(user_input):
    return f"SELECT * FROM users WHERE id = {user_input}"
        """),
        ("xss.js", """
function displayUser(userInput) {
    document.innerHTML = userInput;  // XSS vulnerability
}
        """),
        ("command_injection.py", """
import os
def run_command(cmd):
    os.system(cmd)  // Command injection
        """)
    ]
    
    for filename, content in test_files:
        (test_dir / filename).write_text(content)
    
    try:
        # 初始化扫描器
        scanner = SecurityScanner(
            mode=ScanMode.DEEPSEEK,
            api_key="your-api-key",
            batch_size=2,
            batch_delay=0.5
        )
        
        # 记录开始时间
        start = time.perf_counter()
        
        # 运行扫描
        results = await scanner.scan_directory(str(test_dir))
        
        # 计算总时间
        elapsed = time.perf_counter() - start
        
        # 记录性能指标
        logger.info(f"Total scan time: {elapsed:.2f} seconds")
        logger.info(f"Files scanned: {results['metadata']['files_scanned']}")
        logger.info(f"Average time per file: {elapsed/len(test_files):.2f} seconds")
        logger.info(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
        
    finally:
        # 清理测试文件
        for file in test_dir.glob("*"):
            file.unlink()
        test_dir.rmdir()

if __name__ == "__main__":
    asyncio.run(test_deepseek_performance()) 