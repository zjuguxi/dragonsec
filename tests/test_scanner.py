import pytest
from dragonsec.core.scanner import SecurityScanner, ScanMode
from dragonsec.utils.semgrep import SemgrepRunner
from dragonsec.utils.file_utils import FileContext
from pathlib import Path
from dragonsec.providers.openai import OpenAIProvider
from unittest.mock import patch, MagicMock
import shutil
import asyncio
import os
import sqlite3
import pickle
import logging
import json

@pytest.fixture(scope="session", autouse=True)
def setup_fixtures():
    """Setup fixtures directory"""
    fixtures_dir = Path(__file__).parent / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    return fixtures_dir

def test_semgrep_runner():
    runner = SemgrepRunner()
    assert runner.format_results(None) == []
    assert runner.format_results({"results": []}) == []

@pytest.fixture
def scanner():
    return SecurityScanner(mode=ScanMode.SEMGREP_ONLY)

def test_scanner_initialization(scanner):
    assert scanner.mode == ScanMode.SEMGREP_ONLY
    assert scanner.ai_provider is None

@pytest.fixture
def sample_project_path():
    path = Path(__file__).parent / "fixtures" / "sample_project"
    path.mkdir(parents=True, exist_ok=True)
    return path

@pytest.fixture
def sample_file_path(tmp_path):
    """Create a sample file for testing"""
    file_path = tmp_path / "sample_file.py"
    file_path.write_text("""
def insecure_function():
    password = "hardcoded_password"
    return password
""")
    return str(file_path)

@pytest.mark.asyncio
async def test_scan_directory():
    """Test scanning a directory"""
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    test_dir = Path(__file__).parent / "fixtures" / "test_project"
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # Create test files
    (test_dir / "app.py").write_text("""
def vulnerable_func():
    password = "hardcoded_secret"
    return password
""")
    
    (test_dir / "config.js").write_text("""
const API_KEY = "1234567890";
""")
    
    try:
        results = await scanner.scan_directory(str(test_dir))
        assert "vulnerabilities" in results
        assert "overall_score" in results
        assert "metadata" in results
        assert results["metadata"]["files_scanned"] == 2
    finally:
        shutil.rmtree(test_dir)

@pytest.mark.asyncio
async def test_scan_empty_directory():
    """Test scanning an empty directory"""
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    empty_dir = Path(__file__).parent / "fixtures" / "empty_dir"
    empty_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        results = await scanner.scan_directory(str(empty_dir))
        assert results["overall_score"] == 100
        assert results["summary"] == "No files to scan"
        assert results["metadata"]["files_scanned"] == 0
    finally:
        shutil.rmtree(empty_dir)

@pytest.mark.asyncio
async def test_scan_with_ai():
    """Test scanning with AI enabled"""
    scanner = SecurityScanner(
        mode=ScanMode.OPENAI,
        api_key="test_key",
        batch_size=2,
        batch_delay=0.1
    )
    
    test_file = Path(__file__).parent / "fixtures" / "test.py"
    test_file.write_text("""
def insecure_function(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
""")
    
    try:
        results = await scanner.scan_file(str(test_file))
        assert "vulnerabilities" in results
        vulns = results["vulnerabilities"]
        assert any(v["source"] == "ai" for v in vulns)
    finally:
        test_file.unlink(missing_ok=True)

@pytest.mark.asyncio
async def test_scan_directory(sample_project_path):
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    try:
        results = await scanner.scan_directory(str(sample_project_path))
        assert "vulnerabilities" in results
        assert "overall_score" in results
        assert "summary" in results
    except Exception as e:
        pytest.fail(f"Test failed: {e}")

@pytest.mark.asyncio
async def test_scan_file(sample_file_path):
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    try:
        results = await scanner.scan_file(str(sample_file_path))
        assert "vulnerabilities" in results
    except Exception as e:
        pytest.fail(f"Test failed: {e}")

@patch('dragonsec.providers.openai.OpenAIProvider.analyze_code')
@pytest.mark.asyncio
async def test_scan_with_ai(mock_analyze, sample_file_path):
    # 设置 mock 返回值
    mock_analyze.return_value = {
        "vulnerabilities": [],
        "overall_score": 100
    }
    
    with patch('dragonsec.providers.base.AIProvider._secure_api_key') as mock_secure:
        mock_secure.return_value = "test_key_1234567890123456789012345678901"
        scanner = SecurityScanner(
            mode=ScanMode.OPENAI, 
            api_key="test_key_1234567890123456789012345678901"
        )
        results = await scanner.scan_directory(str(sample_file_path))
        
        assert isinstance(results, dict)
        assert "vulnerabilities" in results
        assert "summary" in results
        assert "overall_score" in results

@pytest.mark.asyncio
async def test_skip_test_files():
    """Test skipping test files"""
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    test_file = Path(__file__).parent / "fixtures" / "test_sample.py"
    test_file.write_text("""
def test_function():
    password = "test_secret"
    return password
""")
    try:
        results = await scanner.scan_file(str(test_file))
        assert len(results["vulnerabilities"]) == 0
    finally:
        test_file.unlink(missing_ok=True)

@pytest.mark.asyncio
async def test_scan_with_cache(sample_file_path):
    """Test scanning with cache enabled"""
    cache_file = "test_cache.json"
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    
    # First scan
    scanner.semgrep_runner.cache_file = cache_file
    results1 = await scanner.scan_file(sample_file_path)
    
    # Second scan should use cache
    results2 = await scanner.scan_file(sample_file_path)
    
    # 移除 scan_duration 字段再比较
    if 'metadata' in results1:
        results1['metadata'].pop('scan_duration', None)
    if 'metadata' in results2:
        results2['metadata'].pop('scan_duration', None)
    
    assert results1 == results2
    
    # Cleanup
    Path(cache_file).unlink(missing_ok=True)

# 在扫描前验证文件
def verify_files_exist(directory: Path, expected_count: int) -> bool:
    """验证目录中的文件数量和内容"""
    files = list(directory.glob("*.py"))
    if len(files) != expected_count:
        return False
    
    # 验证每个文件都有内容
    return all(f.stat().st_size > 0 for f in files)

# @pytest.mark.asyncio
# async def test_scan_with_incremental():
#     """Test incremental scanning"""
#     scanner = SecurityScanner(
#         mode=ScanMode.SEMGREP_ONLY,
#         incremental=True,
#         include_tests=True
#     )
    
#     test_dir = Path(__file__).parent / "fixtures" / "incremental_test"
#     test_dir.mkdir(parents=True, exist_ok=True)
    
#     try:
#         # Create initial files with proper extensions
#         (test_dir / "file1.py").write_text("""
# def test_func():
#     password = 'secret1'
# """)
#         (test_dir / "file2.py").write_text("""
# def another_func():
#     password = 'secret2'
# """)
#         await asyncio.sleep(2)
        
#         # 验证文件创建成功
#         while not verify_files_exist(test_dir, 2):
#             await asyncio.sleep(1)
        
#         # First scan
#         results1 = await scanner.scan_directory(str(test_dir))
#         assert results1["metadata"]["files_scanned"] == 2
        
#         # Modify one file
#         (test_dir / "file1.py").write_text("""
# def test_func():
#     password = 'new_secret'
# """)
#         await asyncio.sleep(2)
        
#         # Second scan should only scan modified file
#         results2 = await scanner.scan_directory(str(test_dir))
#         assert results2["metadata"]["files_scanned"] == 1
#     finally:
#         shutil.rmtree(test_dir)

# @pytest.mark.asyncio
# async def test_scan_with_batch_processing():
#     """Test batch processing of files"""
#     scanner = SecurityScanner(
#         mode=ScanMode.SEMGREP_ONLY,
#         batch_size=2,
#         batch_delay=0.1,
#         include_tests=True,
#         verbose=True  # 添加调试信息
#     )
    
#     test_dir = Path(__file__).parent / "fixtures" / "batch_test"
#     test_dir.mkdir(parents=True, exist_ok=True)
    
#     try:
#         # Create multiple test files with obvious security issues
#         for i in range(5):
#             (test_dir / f"file{i}.py").write_text("""
# import os
# import sqlite3

# def test_func():
#     # Hardcoded credentials - 明显的安全问题
#     API_KEY = "1234567890abcdef"
#     PASSWORD = "super_secret_123"
    
#     # SQL injection - 明显的安全问题
#     user_input = "1' OR '1'='1"
#     conn = sqlite3.connect('test.db')
#     cursor = conn.cursor()
#     cursor.execute("SELECT * FROM users WHERE id = '" + user_input + "'")  # 使用字符串拼接
    
#     # Command injection - 明显的安全问题
#     user_command = "echo 'hello'; rm -rf /"
#     os.system("bash -c '" + user_command + "'")  # 使用字符串拼接
    
#     # 不安全的反序列化
#     import pickle
#     pickle.loads(user_input)
    
#     return PASSWORD
# """)
#         await asyncio.sleep(2)
        
#         # 验证文件创建成功
#         while not verify_files_exist(test_dir, 5):
#             await asyncio.sleep(1)
        
#         results = await scanner.scan_directory(str(test_dir))
#         assert results["metadata"]["files_scanned"] == 5
#         assert len(results["vulnerabilities"]) > 0
#     finally:
#         shutil.rmtree(test_dir)

@pytest.mark.asyncio
async def test_scan_with_different_file_types():
    """Test scanning different file types"""
    # 启用调试日志
    logging.basicConfig(level=logging.DEBUG)
    
    # 创建一个特殊的扫描器，强制包含所有文件类型
    scanner = SecurityScanner(
        mode=ScanMode.SEMGREP_ONLY, 
        verbose=True,
        include_tests=True  # 确保包含测试文件
    )
    
    # 修改 supported_extensions 以包含测试文件类型
    scanner.supported_extensions = {
        'py', 'js', 'java', 'dockerfile',
        # 添加其他扩展名...
    }
    
    test_dir = Path(__file__).parent / "fixtures" / "mixed_files"
    test_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Create files of different types
        files = {
            "app.py": """
def unsafe_sql(user_input):
    return f"SELECT * FROM users WHERE id = {user_input}"
""",
            "config.js": """
const password = "hardcoded_secret";
""",
            "service.java": """
public class Service {
    private static final String API_KEY = "1234567890";
}
""",
            "Dockerfile": """
ENV DB_PASSWORD=secret123
"""
        }
        
        # Create and verify files
        for name, content in files.items():
            file_path = test_dir / name
            file_path.write_text(content)
            print(f"Created file: {file_path}, exists: {file_path.exists()}")
        
        results = await scanner.scan_directory(str(test_dir))
        print(f"Files found: {[str(p) for p in Path(test_dir).glob('*')]}")
        print(f"Scan results: {json.dumps(results, indent=2)}")
        
        assert results["metadata"]["files_scanned"] == 4
        
    finally:
        # 清理测试文件
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)

@pytest.mark.asyncio
async def test_error_handling():
    """Test error handling in scanner"""
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    
    # Test non-existent file
    non_existent = Path(__file__).parent / "not_exists.py"
    result = await scanner.scan_file(str(non_existent))
    
    # 检查返回的结果是否符合预期的错误格式
    assert isinstance(result, dict)
    assert "vulnerabilities" in result
    assert len(result["vulnerabilities"]) == 0  # 应该没有漏洞
    
    # 可以添加更多断言来验证错误处理
    # 例如检查日志输出等

@pytest.mark.asyncio
async def test_scanner_with_invalid_files():
    """Test scanner with invalid files"""
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY, verbose=True)
    test_dir = Path(__file__).parent / "fixtures" / "invalid_files"
    test_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # 创建一些无效文件
        (test_dir / "binary.bin").write_bytes(b'\x00\x01\x02\x03')
        (test_dir / "empty.py").write_text("")
        (test_dir / ".hidden").write_text("hidden file")
        
        results = await scanner.scan_directory(str(test_dir))
        print(f"Test results: {json.dumps(results, indent=2)}")
        
        # 检查是否所有文件都被跳过
        assert results["metadata"]["files_scanned"] == 0
        assert results["metadata"]["skipped_files"] == 3
    finally:
        # 清理测试文件
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)

@pytest.mark.asyncio
async def test_scanner_batch_processing():
    """Test batch processing of files"""
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY, batch_size=2)
    
    # Create test files
    files = [
        "test1.py", "test2.py", "test3.py"
    ]
    results = await scanner.process_batch(files)
    assert len(results) == 3

@pytest.mark.asyncio
async def test_scanner_error_handling():
    """Test scanner error handling"""
    scanner = SecurityScanner()
    
    # Test with non-existent directory
    result = await scanner.scan_directory("/nonexistent/path")
    assert result["overall_score"] == 100
    assert "error" in result["metadata"]
