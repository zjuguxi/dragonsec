import asyncio
import time
from pathlib import Path
from dragonsec.core.scanner import SecurityScanner, ScanMode
import os
import shutil

async def performance_test():
    # 创建测试目录
    test_dir = Path("test_project")
    test_dir.mkdir(exist_ok=True)
    
    # 创建多个测试文件
    for i in range(5):
        file_path = test_dir / f"file_{i}.py"
        with open(file_path, "w") as f:
            f.write(f"""
# Test file {i}
import os
import sqlite3

def unsafe_function_{i}(user_input):
    query = f"SELECT * FROM users WHERE id = '{user_input}'"
    return query

def another_function_{i}():
    password = "secret_{i}"
    return password
""")
    
    # 测试不同模式的性能
    modes = [ScanMode.SEMGREP_ONLY, ScanMode.LOCAL]
    
    for mode in modes:
        print(f"\n测试模式: {mode.value}")
        scanner = SecurityScanner(
            mode=mode,
            verbose=True,
            batch_size=2
        )
        
        start_time = time.time()
        result = await scanner.scan_directory(str(test_dir))
        end_time = time.time()
        
        print(f"  扫描时间: {end_time - start_time:.2f} 秒")
        print(f"  发现漏洞数量: {len(result.get('vulnerabilities', []))}")
        print(f"  安全评分: {result.get('overall_score')}")
    
    # 清理测试目录
    shutil.rmtree(test_dir)

if __name__ == "__main__":
    asyncio.run(performance_test()) 