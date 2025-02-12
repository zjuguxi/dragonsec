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

def test_format_results():
    runner = SemgrepRunner()
    sample_results = {
        "results": [
            {
                "check_id": "python.lang.security.audit.hardcoded-password",
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