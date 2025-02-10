import pytest
from dragonsec.core.scanner import SecurityScanner, ScanMode
from dragonsec.utils.semgrep import SemgrepRunner
from dragonsec.utils.file_utils import FileContext

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
