import pytest
from dragonsec.utils.semgrep import SemgrepRunner
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, call, AsyncMock
import json
import asyncio # Import asyncio for subprocess mocking

# Define a sample Semgrep JSON output for mocking
MOCK_SEMGREP_OUTPUT_BASIC = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.audit.hardcoded-password",
            "path": "mock_file.py",
            "start": {"line": 5},
            "end": {"line": 5},
            "extra": {
                "message": "Hardcoded password detected",
                "severity": "ERROR",
                "metadata": {"cwe": "CWE-798"}
            }
        }
    ],
    "errors": [],
    "paths": []
})

MOCK_SEMGREP_OUTPUT_SQLI = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.sql-injection",
            "path": "sql_injection.py",
            "start": {"line": 2},
            "end": {"line": 2},
            "extra": {
                "message": "SQL injection vulnerability detected",
                "severity": "ERROR",
                "metadata": {"cwe": "CWE-89", "impact": "High", "fix": "Use parameterized queries"}
            }
        }
    ],
    "errors": [],
    "paths": []
})

# Define dict versions for mock return values and cache
MOCK_SEMGREP_DICT_BASIC = json.loads(MOCK_SEMGREP_OUTPUT_BASIC)
MOCK_SEMGREP_DICT_SQLI = json.loads(MOCK_SEMGREP_OUTPUT_SQLI)


@pytest.fixture
def sample_file_path():
    return Path(__file__).parent.parent / "fixtures" / "sample_file.py"


# Helper to create a mock process for asyncio.create_subprocess_exec
def create_mock_process(stdout_str: str, returncode: int = 0, stderr_str: str = ""):
    mock_process = AsyncMock(spec=asyncio.subprocess.Process)
    mock_process.returncode = returncode
    # communicate returns a tuple of (stdout_bytes, stderr_bytes)
    mock_process.communicate = AsyncMock(
        return_value=(stdout_str.encode('utf-8'), stderr_str.encode('utf-8'))
    )
    mock_process.kill = MagicMock()
    return mock_process


@pytest.mark.asyncio
@patch('asyncio.create_subprocess_exec')
@patch.object(SemgrepRunner, '_parse_semgrep_output') # Mock the parser
async def test_run_scan(mock_parse_output, mock_create_subprocess, sample_file_path):
    """Test basic semgrep scan mocking parser"""
    # Mock create_subprocess to return some valid JSON output string
    mock_create_subprocess.return_value = create_mock_process(MOCK_SEMGREP_OUTPUT_BASIC)
    # Mock the parser to return the final dictionary WITH CORRECT SEVERITY
    expected_parsed_dict = {
        "results": [{
            "check_id": "python.lang.security.audit.audit.hardcoded-password",
            "path": "mock_file.py",
            "start": {"line": 5}, "end": {"line": 5},
            "extra": {
                "message": "Hardcoded password detected",
                "severity": "ERROR", # Keep original severity here
                "metadata": {"cwe": "CWE-798"}
            }
        }]
        # Add other keys like 'errors', 'paths' if _parse_semgrep_output returns them
    }
    mock_parse_output.return_value = expected_parsed_dict

    runner = SemgrepRunner(workers=1)
    results = await runner.run_scan(str(sample_file_path))

    # Assert subprocess was called
    mock_create_subprocess.assert_called_once()
    # Assert parser was called with the raw output
    mock_parse_output.assert_called_once_with(MOCK_SEMGREP_OUTPUT_BASIC)

    # Assert the structure and content based on FORMATTED results
    # format_results will use the dict from the mocked parser
    assert "results" in results # The result *is* the dict from mock_parse_output
    formatted = runner.format_results(results)
    assert len(formatted) == 1
    assert formatted[0]["type"] == "python.lang.security.audit.audit.hardcoded-password"
    assert formatted[0]["severity"] == 9 # format_results converts ERROR to 9
    assert formatted[0]["file"] == "mock_file.py"


@pytest.mark.asyncio
@patch('asyncio.create_subprocess_exec')
@patch.object(SemgrepRunner, '_parse_semgrep_output') # Mock the parser
async def test_run_scan_with_rules(mock_parse_output, mock_create_subprocess, fixtures_dir):
    """Test running semgrep scan with specific finding mocking parser"""
    runner = SemgrepRunner(workers=1)
    test_file = fixtures_dir / "sql_injection.py"
    test_file.write_text(
        """
    def unsafe_query(user_input):
        query = f"SELECT * FROM users WHERE id = {user_input}" # Potential SQLi
        return query
    """
    )

    # Mock create_subprocess
    mock_create_subprocess.return_value = create_mock_process(MOCK_SEMGREP_OUTPUT_SQLI)
    # Mock the parser to return the final dict WITH CORRECT RECOMMENDATION
    expected_parsed_dict = {
        "results": [{
            "check_id": "python.lang.security.audit.sql-injection",
            "path": "sql_injection.py",
            "start": {"line": 2}, "end": {"line": 2},
            "extra": {
                "message": "SQL injection vulnerability detected",
                "severity": "ERROR",
                "metadata": {
                    "cwe": "CWE-89",
                    "impact": "High",
                    # Ensure the desired recommendation is here
                    "fix": "Use parameterized queries"
                }
            }
        }]
    }
    mock_parse_output.return_value = expected_parsed_dict

    try:
        results = await runner.run_scan(str(test_file))
        # Assert subprocess call
        mock_create_subprocess.assert_called_once()
        # Assert parser call
        mock_parse_output.assert_called_once_with(MOCK_SEMGREP_OUTPUT_SQLI)

        # Assert the formatted results for SQLi
        assert "results" in results
        formatted = runner.format_results(results)
        assert len(formatted) == 1
        assert formatted[0]["type"] == "python.lang.security.audit.sql-injection"
        # Severity assertion relies on format_results converting the 'ERROR' from mock parser's dict
        assert formatted[0]["severity"] == 9
        assert formatted[0]["file"] == "sql_injection.py"
        # Recommendation comes from format_results processing the mock parser's dict
        assert formatted[0]["recommendation"] == "Use parameterized queries"
    finally:
        test_file.unlink()


def test_format_results():
    runner = SemgrepRunner()
    sample_results = {
        "results": [
            {
                "check_id": "python.lang.security.audit.audit.hardcoded-password",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "Hardcoded password",
                    "metadata": {
                        "impact": "High security risk",
                        "fix": "Use environment variables",
                    },
                },
            }
        ]
    }
    formatted = runner.format_results(sample_results)
    assert isinstance(formatted, list)
    assert len(formatted) > 0
    assert formatted[0]["source"] == "semgrep"


@pytest.fixture(scope="session")
def fixtures_dir():
    path = Path(__file__).parent / "fixtures"
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_format_results_with_metadata():
    """Test formatting results with metadata"""
    runner = SemgrepRunner()
    sample_results = {
        "results": [
            {
                "check_id": "python.lang.security.audit.sql-injection",
                "path": "test.py",
                "start": {"line": 1},
                "extra": {
                    "severity": "high",
                    "message": "SQL injection detected",
                    "metadata": {
                        "cwe": "CWE-89",
                        "impact": "High",
                        "fix": "Use parameterized queries",
                    },
                },
            }
        ]
    }

    formatted = runner.format_results(sample_results)
    assert formatted[0]["severity"] == 8
    assert "risk_analysis" in formatted[0]
    assert "recommendation" in formatted[0]


@pytest.mark.asyncio
@patch.object(SemgrepRunner, '_get_file_hash')
@patch('asyncio.create_subprocess_exec')
# Mock the parser method to control the final dict structure
@patch.object(SemgrepRunner, '_parse_semgrep_output')
async def test_run_scan_with_cache(mock_parse_output, mock_create_subprocess, mock_get_hash):
    """Test scanning with cache enabled using mocks and mocking parser"""
    # Mock the parser to return the final structure we expect in results and cache
    mock_parse_output.return_value = MOCK_SEMGREP_DICT_BASIC

    initial_cache = {"hash1": MOCK_SEMGREP_DICT_BASIC}
    runner = SemgrepRunner(cache=initial_cache.copy())
    test_file = Path(__file__).parent / "fixtures" / "test_cache_file.py"
    test_file.write_text("print('test cache')")

    try:
        # === Test Cache Hit ===
        mock_get_hash.return_value = "hash1"
        results_hit = await runner.run_scan(str(test_file))
        # Assert: subprocess and parser should NOT be called
        mock_create_subprocess.assert_not_called()
        mock_parse_output.assert_not_called()
        assert results_hit == initial_cache["hash1"]

        mock_create_subprocess.reset_mock()
        mock_parse_output.reset_mock()

        # === Test Cache Miss ===
        mock_get_hash.return_value = "hash2"
        # Mock the subprocess call (its output doesn't strictly matter now)
        mock_create_subprocess.return_value = create_mock_process(MOCK_SEMGREP_OUTPUT_BASIC)
        # parse_output is already mocked to return MOCK_SEMGREP_DICT_BASIC

        results_miss = await runner.run_scan(str(test_file))

        # Assert: subprocess SHOULD be called
        mock_create_subprocess.assert_called_once()
        # Assert: parser SHOULD be called (with the stdout from the process mock)
        mock_parse_output.assert_called_once_with(MOCK_SEMGREP_OUTPUT_BASIC)
        # Assert: Results should match the output from the mocked parser
        assert results_miss == MOCK_SEMGREP_DICT_BASIC
        # Assert: Cache should be updated with the result from the parser
        assert runner.cache.get("hash2") == MOCK_SEMGREP_DICT_BASIC

    finally:
        test_file.unlink(missing_ok=True)


def test_convert_severity():
    """Test severity conversion"""
    runner = SemgrepRunner()
    assert runner._convert_severity("error") == 9
    assert runner._convert_severity("warning") == 6
    assert runner._convert_severity("info") == 3
    assert runner._convert_severity("unknown") == 5
