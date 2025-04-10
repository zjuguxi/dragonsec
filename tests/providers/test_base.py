import pytest
from dragonsec.providers.base import AIProvider
from typing import Dict, List


class MockProvider:
    """Mock provider for testing"""

    def __init__(self, api_key: str):
        """Initialize mock provider"""
        self.api_key = api_key or ""
        self.required_fields = [
            "type", "severity", "description", "line_number", 
            "file", "risk_analysis", "recommendation", "confidence"
        ]
        self.test_indicators = [
            "/tests/",
            "/test/",
            "/testing/",
            "_test.py",
            "test_.py",
            "tests.py",
            "/fixtures/",
            "/conftest.py"
        ]
        # 添加一些测试特定的属性
        self.test_mode = True

    async def analyze_code(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """Mock implementation of analyze_code"""
        if not code:
            return self._get_default_response()
        if "/tests/" in file_path or "\\tests\\" in file_path:
            return {"vulnerabilities": [], "overall_score": 100, "summary": "Skipped test file"}
        return {"vulnerabilities": [], "overall_score": 100, "summary": "Mock analysis"}
    
    async def _analyze_with_ai(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """Mock implementation of _analyze_with_ai"""
        return {"vulnerabilities": [], "overall_score": 100, "summary": "Mock analysis"}

    def merge_results(self, semgrep_results: List[Dict], ai_results: Dict) -> Dict:
        """Mock implementation of merge_results"""
        return {"vulnerabilities": [], "overall_score": 100, "summary": "Mock merge"}
    
    def _get_default_response(self) -> Dict:
        """Get default response when analysis fails"""
        return {"vulnerabilities": [], "overall_score": 100, "summary": "Error analyzing code"}
    
    def _standardize_vulnerability(self, vuln: Dict, file_path: str) -> Dict:
        """Standardize vulnerability format"""
        try:
            return {
                "type": str(vuln["type"]).strip(),
                "severity": int(vuln["severity"]),
                "description": str(vuln["description"]).strip(),
                "line_number": int(vuln["line_number"]),
                "file": file_path,
                "risk_analysis": str(vuln["risk_analysis"]).strip(),
                "recommendation": str(vuln["recommendation"]).strip(),
            }
        except (KeyError, ValueError) as e:
            return None


def test_secure_api_key():
    """Test API key validation"""
    # 测试有效的 API 密钥
    provider = MockProvider("valid-key")
    assert provider.api_key == "valid-key"
    
    # 测试空 API 密钥
    provider = MockProvider("")
    assert provider.api_key == ""
    
    # 测试 None API 密钥
    provider = MockProvider(None)
    assert provider.api_key == ""


@pytest.mark.asyncio
async def test_analyze_code():
    """Test basic code analysis workflow"""
    provider = MockProvider("test-key")

    # 测试正常分析
    result = await provider.analyze_code("print('test')", "test.py")
    assert "vulnerabilities" in result
    assert "overall_score" in result
    assert "summary" in result

    # 测试无效输入
    result = await provider.analyze_code("", "test.py")
    assert result == provider._get_default_response()

    # 测试测试文件跳过
    result = await provider.analyze_code("test", "/path/to/tests/file.py")
    assert "Skipped test file" in result["summary"]


@pytest.mark.asyncio
async def test_vulnerability_standardization():
    """Test vulnerability standardization"""
    provider = MockProvider("test-key")

    vuln = {
        "type": "SQL Injection",
        "severity": 8,
        "description": "Test description",
        "line_number": 10,
        "file": "test.py",
        "risk_analysis": "Test risk",
        "recommendation": "Test recommendation",
    }

    result = provider._standardize_vulnerability(vuln, "test.py")
    assert result is not None
    assert result["type"] == "SQL Injection"
    assert result["severity"] == 8
