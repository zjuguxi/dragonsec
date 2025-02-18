import pytest
from unittest.mock import AsyncMock, patch
from dragonsec.providers.deepseek import DeepseekProvider
from tests.providers.test_openai import (
    test_analyze_code_success as test_openai_analyze_success,
    test_analyze_code_error as test_openai_analyze_error,
)

@pytest.fixture
def openai_provider(deepseek_provider):
    """重用 OpenAI 测试的 fixture，但返回 Deepseek provider"""
    return deepseek_provider

@pytest.fixture
def deepseek_provider():
    """Create a test instance of DeepseekProvider"""
    with patch('dragonsec.providers.base.AIProvider._secure_api_key') as mock_secure:
        mock_secure.return_value = "test_key"
        provider = DeepseekProvider("test_key")
        # 验证初始化参数
        assert provider.model == "deepseek-r1"
        assert "dashscope.aliyuncs.com" in str(provider.client.base_url)
        return provider

# 重用 OpenAI 的测试
test_analyze_code_success = test_openai_analyze_success
test_analyze_code_error = test_openai_analyze_error

@pytest.mark.asyncio
async def test_deepseek_specific_response_format(deepseek_provider):
    """Test Deepseek specific response format handling"""
    # 创建一个异步 mock 函数
    async def mock_create(*args, **kwargs):
        return AsyncMock(
            choices=[
                AsyncMock(
                    message=AsyncMock(
                        content="""
                        {
                            "vulnerabilities": [
                                {
                                    "type": "sql_injection",
                                    "severity": 8,
                                    "description": "SQL injection found",
                                    "line_number": 15,
                                    "risk_analysis": "High risk",
                                    "recommendation": "Use parameterized queries"
                                }
                            ]
                        }
                        """
                    )
                )
            ]
        )
    
    # 使用异步 mock 函数
    with patch('openai.resources.chat.completions.AsyncCompletions.create', 
              new=mock_create):
        result = await deepseek_provider.analyze_code(
            code="query = f'SELECT * FROM users WHERE id = {user_input}'",
            file_path="test.py",
            context={}
        )
        
        assert "vulnerabilities" in result
        assert len(result["vulnerabilities"]) == 1
        vuln = result["vulnerabilities"][0]
        assert vuln["type"] == "sql_injection"
        assert vuln["severity"] == 8

def test_deepseek_specific_init():
    """Test Deepseek specific initialization"""
    provider = DeepseekProvider("test_key")
    assert provider.model == "deepseek-r1"
    assert "dashscope.aliyuncs.com" in str(provider.client.base_url)

def test_calculate_security_score(deepseek_provider):
    """Test security score calculation"""
    vulnerabilities = [
        {"severity": 8},
        {"severity": 6},
        {"severity": 4}
    ]
    
    score = deepseek_provider._calculate_security_score(vulnerabilities)
    assert 0 <= score <= 100
    assert score == round(100 - (6 * 10), 2)  # 平均严重度为 6

def test_empty_vulnerabilities_score(deepseek_provider):
    """Test security score with no vulnerabilities"""
    score = deepseek_provider._calculate_security_score([])
    assert score == 100.0 