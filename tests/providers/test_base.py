import pytest
from dragonsec.providers.base import AIProvider
from typing import Dict, List

class MockProvider(AIProvider):
    """Mock provider for testing"""
    async def _analyze_with_ai(self, code: str, file_path: str, context: Dict = None) -> Dict:
        return {
            "vulnerabilities": [],
            "overall_score": 100,
            "summary": "Mock analysis"
        }
    
    def merge_results(self, semgrep_results: List[Dict], ai_results: Dict) -> Dict:
        """Mock implementation of merge_results"""
        return {
            "vulnerabilities": [],
            "overall_score": 100,
            "summary": "Mock merge"
        }

def test_secure_api_key():
    """Test API key validation"""
    # 测试有效的 API 密钥
    provider = MockProvider("valid-key")
    assert provider.api_key == "valid-key"
    
    # 测试无效的 API 密钥
    with pytest.raises(ValueError, match="API key is required"):
        MockProvider("")
    with pytest.raises(ValueError, match="API key is required"):
        MockProvider(None)

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
        "recommendation": "Test recommendation"
    }
    
    result = provider._standardize_vulnerability(vuln, "test.py")
    assert result is not None
    assert result["type"] == "SQL Injection"
    assert result["severity"] == 8 