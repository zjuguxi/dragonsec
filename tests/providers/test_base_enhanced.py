import pytest
import json
from unittest.mock import patch, MagicMock
from dragonsec.providers.base import AIProvider, create_error_response, handle_api_errors
from typing import Dict, List
import asyncio


# 创建一个具体的AIProvider子类用于测试
class TestProvider(AIProvider):
    """Concrete implementation of AIProvider for testing"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        
    async def _analyze_with_ai(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """Required implementation of abstract method"""
        return {
            "vulnerabilities": [
                {
                    "type": "Test Vulnerability",
                    "severity": 7,
                    "description": "Test vulnerability description",
                    "line_number": 10,
                    "risk_analysis": "This is a test risk analysis",
                    "recommendation": "This is a test recommendation"
                }
            ],
            "overall_score": 90,
            "summary": "Test analysis summary"
        }
        
    # Add method for testing handle_api_errors decorator
    @handle_api_errors
    async def test_api_method(self, should_fail: bool = False):
        """Test method to verify error handling decorator"""
        if should_fail:
            raise Exception("Test exception")
        return {"status": "success"}


def test_create_error_response():
    """Test create_error_response function"""
    # Test basic error response
    response = create_error_response("Test error")
    assert response["summary"] == "Test error"
    assert response["error"] == "Test error"
    assert response["overall_score"] == 100
    assert len(response["vulnerabilities"]) == 0
    
    # Test with custom score
    response = create_error_response("Test error", score=50)
    assert response["overall_score"] == 50
    
    # Test with metadata
    response = create_error_response("Test error", include_metadata=True)
    assert "metadata" in response
    assert response["metadata"]["error"] == "Test error"
    assert response["metadata"]["files_scanned"] == 0


@pytest.mark.asyncio
async def test_handle_api_errors_decorator():
    """Test handle_api_errors decorator"""
    provider = TestProvider("test-key")
    
    # Test successful execution
    result = await provider.test_api_method()
    assert result["status"] == "success"
    
    # Test error handling
    result = await provider.test_api_method(should_fail=True)
    assert "vulnerabilities" in result
    assert "error" in result
    assert "Failed to analyze code" in result["summary"] or "API call failed" in result["summary"]


def test_secure_api_key():
    """Test _secure_api_key method"""
    provider = TestProvider("valid-key")
    assert provider.api_key == "valid-key"
    
    # Test with whitespace
    provider = TestProvider("  spaced-key  ")
    assert provider.api_key == "spaced-key"
    
    # Test with empty key
    provider = TestProvider("")
    assert provider.api_key == ""
    
    # Test with None key
    provider = TestProvider(None)
    assert provider.api_key == ""
    
    # Test with very short key
    provider = TestProvider("ab")
    assert provider.api_key == "ab"


def test_system_prompt():
    """Test system_prompt property"""
    provider = TestProvider("test-key")
    prompt = provider.system_prompt
    
    # Verify the prompt contains key security principles
    assert "Context Understanding" in prompt
    assert "Code Pattern Recognition" in prompt
    assert "Risk Assessment Framework" in prompt


def test_standardize_vulnerability():
    """Test _standardize_vulnerability method"""
    provider = TestProvider("test-key")
    
    # Test valid vulnerability
    vuln = {
        "type": "SQL Injection",
        "severity": 8,
        "description": "Test description",
        "line_number": 10,
        "risk_analysis": "Test risk",
        "recommendation": "Test recommendation",
    }
    
    result = provider._standardize_vulnerability(vuln, "test_file.py")
    assert result["type"] == "SQL Injection"
    assert result["severity"] == 8
    assert result["file"] == "test_file.py"
    
    # Test invalid vulnerability (missing fields)
    invalid_vuln = {
        "type": "SQL Injection",
        "description": "Test description",
        # Missing severity and line_number
    }
    
    result = provider._standardize_vulnerability(invalid_vuln, "test_file.py")
    assert result is None
    
    # Test with string severity that can be converted to int
    vuln_str_severity = {
        "type": "SQL Injection",
        "severity": "8",
        "description": "Test description",
        "line_number": 10,
        "risk_analysis": "Test risk",
        "recommendation": "Test recommendation",
    }
    
    result = provider._standardize_vulnerability(vuln_str_severity, "test_file.py")
    assert result["severity"] == 8
    
    # Test with whitespace in fields that should be stripped
    vuln_with_whitespace = {
        "type": "  SQL Injection  ",
        "severity": 8,
        "description": "  Test description  ",
        "line_number": 10,
        "risk_analysis": "  Test risk  ",
        "recommendation": "  Test recommendation  ",
    }
    
    result = provider._standardize_vulnerability(vuln_with_whitespace, "test_file.py")
    assert result["type"] == "SQL Injection"
    assert result["description"] == "Test description"


def test_calculate_security_score():
    """Test _calculate_security_score method"""
    provider = TestProvider("test-key")
    
    # Test with no vulnerabilities
    score = provider._calculate_security_score([])
    assert score == 100
    
    # Test with one critical vulnerability
    vulns = [{"severity": 10}]
    score = provider._calculate_security_score(vulns)
    assert score == 85
    
    # Test with multiple vulnerabilities of different severities
    vulns = [
        {"severity": 10},  # Critical: -15
        {"severity": 8},   # High: -10
        {"severity": 5},   # Medium: -5
        {"severity": 2},   # Low: -2
    ]
    score = provider._calculate_security_score(vulns)
    assert score == 68
    
    # Test score cannot go below 0
    vulns = [{"severity": 10} for _ in range(10)]  # 10 critical vulnerabilities
    score = provider._calculate_security_score(vulns)
    assert score == 0


def test_is_test_file():
    """Test _is_test_file method"""
    provider = TestProvider("test-key")
    
    # Test various test file paths
    assert provider._is_test_file("/path/to/tests/test_file.py") is True
    assert provider._is_test_file("C:\\path\\to\\tests\\test_file.py") is True
    
    # 修正测试，只检查目录名，不检查文件名
    assert provider._is_test_file("/path/to/test/file.py") is True
    # 注意：根据实际业务逻辑，file_test.py 会被判断为测试文件，因为它包含 "test" 
    assert provider._is_test_file("/path/to/file_test.py") is True
    
    # Test non-test file paths
    assert provider._is_test_file("/path/to/production.py") is False
    assert provider._is_test_file("/path/to/source.py") is False
    
    # Test conftest.py
    assert provider._is_test_file("/path/to/conftest.py") is True


@pytest.mark.asyncio
async def test_analyze_code():
    """Test analyze_code method"""
    provider = TestProvider("test-key")
    
    # Test valid code analysis
    result = await provider.analyze_code("def test(): pass", "file.py")
    assert "vulnerabilities" in result
    assert result["vulnerabilities"][0]["source"] == "ai"
    assert result["vulnerabilities"][0]["file"] == "file.py"
    
    # Test with empty code
    result = await provider.analyze_code("", "file.py")
    assert "vulnerabilities" in result
    assert len(result["vulnerabilities"]) == 0
    
    # Test with None code
    result = await provider.analyze_code(None, "file.py")
    assert "vulnerabilities" in result
    assert len(result["vulnerabilities"]) == 0
    
    # Test with test file
    result = await provider.analyze_code("def test(): pass", "/path/to/tests/file.py")
    assert result["summary"] == "Skipped test file"
    assert len(result["vulnerabilities"]) == 0
    assert result["overall_score"] == 100


@pytest.mark.asyncio
async def test_deduplicate_vulnerabilities():
    """Test deduplicate_vulnerabilities method"""
    provider = TestProvider("test-key")
    
    # Test with empty list
    result = await provider.deduplicate_vulnerabilities([])
    assert len(result) == 0
    
    # Test with unique vulnerabilities
    vulns = [
        {"type": "SQL Injection", "file": "file1.py", "line_number": 10},
        {"type": "XSS", "file": "file2.py", "line_number": 20},
    ]
    result = await provider.deduplicate_vulnerabilities(vulns)
    assert len(result) == 2
    
    # Test with duplicate vulnerabilities
    vulns = [
        {"type": "SQL Injection", "file": "file1.py", "line_number": 10},
        {"type": "SQL Injection", "file": "file1.py", "line_number": 10},  # Duplicate
        {"type": "XSS", "file": "file2.py", "line_number": 20},
    ]
    result = await provider.deduplicate_vulnerabilities(vulns)
    assert len(result) == 2
    
    # Test with similar vulnerabilities but different fields
    vulns = [
        {"type": "SQL Injection", "file": "file1.py", "line_number": 10},
        {"type": "SQL Injection", "file": "file1.py", "line_number": 15},  # Different line
        {"type": "SQL Injection", "file": "file2.py", "line_number": 10},  # Different file
    ]
    result = await provider.deduplicate_vulnerabilities(vulns)
    assert len(result) == 3


def test_prepare_prompt():
    """Test _prepare_prompt method"""
    provider = TestProvider("test-key")
    
    # Test without context
    prompt = provider._prepare_prompt("print('test')")
    assert "print('test')" in prompt
    assert "No additional context" in prompt
    
    # Test with context
    context = {"file_type": "python", "framework": "flask"}
    prompt = provider._prepare_prompt("print('test')", context)
    assert "print('test')" in prompt
    assert json.dumps(context) in prompt


def test_get_decision_prompt():
    """Test _get_decision_prompt method"""
    provider = TestProvider("test-key")
    prompt = provider._get_decision_prompt()
    
    # Verify the prompt contains the decision tree
    assert "decision tree" in prompt
    assert "Is it a code pattern?" in prompt
    assert "Is it actual data?" in prompt


def test_get_context_categories():
    """Test _get_context_categories method"""
    provider = TestProvider("test-key")
    categories = provider._get_context_categories()
    
    # Verify the categories are present
    assert "Security Context Categories" in categories
    assert "Infrastructure Code" in categories
    assert "Application Code" in categories
    assert "Test Code" in categories 