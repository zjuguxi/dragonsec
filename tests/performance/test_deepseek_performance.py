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
    """Test Deepseek provider performance"""
    scanner = SecurityScanner(
        mode=ScanMode.DEEPSEEK,
        api_key="test-key",
        batch_size=2,  # 使用小批次进行测试
        batch_delay=0.1
    )
    
    # 使用测试文件
    test_file = Path(__file__).parent.parent / "fixtures" / "sample_file.py"
    start_time = time.perf_counter()
    
    result = await scanner.scan_file(str(test_file))
    
    duration = time.perf_counter() - start_time
    assert duration < 60  # 确保单文件扫描不超过60秒

if __name__ == "__main__":
    asyncio.run(test_deepseek_performance()) 