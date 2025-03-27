import asyncio
import time
from pathlib import Path
from dragonsec.core.scanner import SecurityScanner, ScanMode
import os
import shutil

async def performance_test():
    # Create test directory
    test_dir = Path("test_project")
    test_dir.mkdir(exist_ok=True)
    
    # Create multiple test files
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
    
    # Test different modes performance
    modes = [ScanMode.SEMGREP_ONLY, ScanMode.LOCAL]
    
    for mode in modes:
        print(f"\nTest mode: {mode.value}")
        scanner = SecurityScanner(
            mode=mode,
            verbose=True,
            batch_size=2
        )
        
        start_time = time.time()
        result = await scanner.scan_directory(str(test_dir))
        end_time = time.time()
        
        print(f"   Scan time: {end_time - start_time:.2f} seconds")
        print(f"   Vulnerability count: {len(result.get('vulnerabilities', []))}")
        print(f"   Security score: {result.get('overall_score')}")
    
    # Clean up test directory
    shutil.rmtree(test_dir)

if __name__ == "__main__":
    asyncio.run(performance_test()) 