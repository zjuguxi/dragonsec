import pytest
import os
import json
from pathlib import Path

@pytest.fixture
def test_cache():
    """Create a test cache dictionary"""
    return {}

@pytest.fixture
def test_files_dir():
    """Create a temporary directory with test files"""
    test_dir = Path(__file__).parent / "test_files"
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # 创建测试文件
    test_files = {
        "test.py": """
def insecure_function():
    password = "hardcoded_password"
    return password
""",
        "test.js": """
const secret = 'api_key_123456';
console.log(secret);
""",
        "test.java": """
public class Test {
    private static final String PASSWORD = "secret123";
}
"""
    }
    
    # 写入测试文件
    for filename, content in test_files.items():
        file_path = test_dir / filename
        file_path.write_text(content)
    
    yield test_dir
    
    # 清理测试文件
    for file_path in test_dir.glob("*"):
        file_path.unlink()
    test_dir.rmdir()

@pytest.fixture
def mock_semgrep_results():
    """Mock Semgrep scan results"""
    return {
        "results": [
            {
                "check_id": "python.lang.security.audit.hardcoded-password",
                "path": "test.py",
                "start": {"line": 2},
                "extra": {
                    "severity": "WARNING",
                    "message": "Hardcoded password found",
                    "metadata": {
                        "impact": "High security risk",
                        "fix": "Use environment variables or secure configuration"
                    }
                }
            }
        ]
    }

@pytest.fixture
def mock_ai_results():
    """Mock AI analysis results"""
    return [
        {
            "source": "ai",
            "type": "hardcoded_secret",
            "severity": 8,
            "description": "Hardcoded password detected",
            "line_number": 2,
            "file": "test.py",
            "risk_analysis": "High risk of credential exposure",
            "recommendation": "Use secure secret management"
        }
    ]

@pytest.fixture(scope="session")
def fixtures_dir():
    path = Path(__file__).parent / "fixtures"
    path.mkdir(parents=True, exist_ok=True)
    return path

@pytest.fixture
def sample_file_path(fixtures_dir):
    """Create a sample file for testing"""
    file_path = fixtures_dir / "sample.py"
    file_path.write_text("""
def vulnerable_function():
    password = "hardcoded_secret"  # 这是一个安全问题
    api_key = "1234567890"        # 这也是一个安全问题
    return password
""")
    yield file_path
    # 清理文件
    file_path.unlink(missing_ok=True) 