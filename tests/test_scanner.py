import pytest
from dragonsec.core.scanner import SecurityScanner, ScanMode
from dragonsec.utils.semgrep import SemgrepRunner
from dragonsec.utils.file_utils import FileContext
from pathlib import Path
from dragonsec.providers.openai import OpenAIProvider
from unittest.mock import patch, MagicMock

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
def sample_file_path():
    path = Path(__file__).parent / "fixtures" / "sample_file.py"
    if not path.exists():
        path.write_text("""
def insecure_function():
    password = "hardcoded_password"
    return password

def sql_query(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
""")
    return path

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
    
    # 创建一个非测试文件
    test_file = Path(__file__).parent / "fixtures" / "regular_file.py"
    test_file.write_text("""
    def some_function():
        return "Hello World"
    """)
    
    try:
        scanner = SecurityScanner(mode=ScanMode.OPENAI, api_key="test-key")
        results = await scanner.scan_directory(str(test_file))
        
        assert isinstance(results, dict)
        assert "vulnerabilities" in results
        assert "summary" in results
        assert "overall_score" in results
    finally:
        # 清理测试文件
        test_file.unlink(missing_ok=True)

@pytest.mark.asyncio
async def test_skip_test_files():
    """Test skipping test files"""
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    test_file = Path(__file__).parent / "fixtures" / "test_sample.py"
    results = await scanner.scan_file(str(test_file))
    assert len(results["vulnerabilities"]) == 0

@pytest.mark.asyncio
async def test_scan_with_cache():
    """Test scanning with cache enabled"""
    cache_file = "test_cache.json"
    scanner = SecurityScanner(mode=ScanMode.SEMGREP_ONLY)
    
    # First scan
    scanner.semgrep_runner.cache_file = cache_file
    results1 = await scanner.scan_file(str(sample_file_path))
    
    # Second scan should use cache
    results2 = await scanner.scan_file(str(sample_file_path))
    assert results1 == results2
    
    # Cleanup
    Path(cache_file).unlink(missing_ok=True)
