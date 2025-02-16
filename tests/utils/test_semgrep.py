import pytest
from dragonsec.utils.semgrep import SemgrepRunner
from pathlib import Path

@pytest.fixture
def sample_file_path():
    return Path(__file__).parent.parent / "fixtures" / "sample_file.py"

@pytest.mark.asyncio
async def test_run_scan(sample_file_path):
    runner = SemgrepRunner(verbose=True)
    try:
        results = await runner.run_scan(str(sample_file_path))
        assert "results" in results
    except Exception as e:
        pytest.fail(f"Test failed: {e}")

@pytest.mark.asyncio
async def test_run_scan_with_rules(fixtures_dir):
    """Test running semgrep scan with custom rules"""
    runner = SemgrepRunner(workers=1)
    
    # Create test file with SQL injection
    test_file = fixtures_dir / "sql_injection.py"
    test_file.write_text("""
    def unsafe_query(user_input):
        query = f"SELECT * FROM users WHERE id = {user_input}"
        return query
    """)
    
    results = await runner.run_scan(str(test_file))
    assert "results" in results
    assert isinstance(results["results"], list)
    
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
                        "fix": "Use environment variables"
                    }
                }
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
                        "fix": "Use parameterized queries"
                    }
                }
            }
        ]
    }
    
    formatted = runner.format_results(sample_results)
    assert formatted[0]["severity"] == 8
    assert "risk_analysis" in formatted[0]
    assert "recommendation" in formatted[0]

@pytest.mark.asyncio
async def test_run_scan_with_cache():
    """Test scanning with cache enabled"""
    runner = SemgrepRunner(cache={"test_hash": {"results": []}})
    test_file = Path(__file__).parent / "fixtures" / "test.py"
    test_file.write_text("print('test')")
    
    try:
        # First scan should use cache
        file_hash = runner._get_file_hash(str(test_file))
        runner.cache[file_hash] = {"results": [{"test": "cached"}]}
        results = await runner.run_scan(str(test_file))
        assert results == {"results": [{"test": "cached"}]}
        
        # Modified file should trigger new scan
        test_file.write_text("print('modified')")
        results = await runner.run_scan(str(test_file))
        assert "results" in results
        assert results != {"results": [{"test": "cached"}]}
    finally:
        test_file.unlink(missing_ok=True)

def test_convert_severity():
    """Test severity conversion"""
    runner = SemgrepRunner()
    assert runner._convert_severity("error") == 9
    assert runner._convert_severity("warning") == 6
    assert runner._convert_severity("info") == 3
    assert runner._convert_severity("unknown") == 5 