import pytest
from dragonsec.core.scanner import SecurityScanner, ScanMode
from dragonsec.utils.semgrep import SemgrepRunner
from dragonsec.utils.file_utils import FileContext
from pathlib import Path

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
