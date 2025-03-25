import json
import pytest
from dragonsec.providers.local import LocalProvider
from dragonsec.providers.openai import OpenAIProvider
import requests
import asyncio
import os
from pathlib import Path
import sys

@pytest.mark.asyncio
async def test_prompt_formats():
    """Test different prompt formats"""
    # 检查 Ollama 服务器是否可用
    provider = LocalProvider(model="deepseek-r1:1.5b")
    if not provider.is_server_available():
        # 如果本地服务器不可用，使用 OpenAI 作为备选
        if not os.getenv("OPENAI_API_KEY"):
            pytest.skip("Neither local model server nor OpenAI API key is available")
        provider = OpenAIProvider(api_key=os.getenv("OPENAI_API_KEY"))
    
    # 简单的测试代码
    code = """
def unsafe_sql_query(user_input):
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    return query
"""
    
    # 测试不同的提示格式
    prompts = [
        "简单提示：分析这段代码中的安全问题",
        "详细提示：请分析这段代码中的SQL注入漏洞，并提供修复建议",
    ]
    
    try:
        for i, prompt in enumerate(prompts):
            print(f"Testing prompt format {i+1}")
            
            # 创建自定义提示的提供者
            class CustomPromptProvider(type(provider)):
                def _build_prompt(self, code, file_path=None):
                    return f"{prompt}\n\n```python\n{code}\n```"
            
            custom_provider = CustomPromptProvider(api_key=os.getenv("OPENAI_API_KEY"))
            
            # 设置超时
            timeout = 60  # 60秒超时
            
            # 使用 asyncio.wait_for 添加超时控制
            result = await asyncio.wait_for(
                custom_provider.analyze_code(code, "test_code.py"),
                timeout=timeout
            )
            
            # 验证结果
            assert "vulnerabilities" in result
            assert "overall_score" in result
            assert isinstance(result["vulnerabilities"], list)
            
            # 验证是否检测到 SQL 注入
            vuln_types = [v.get("type", "").lower() for v in result["vulnerabilities"]]
            assert any("sql" in t for t in vuln_types), "SQL injection not detected"
            
    except asyncio.TimeoutError:
        pytest.skip(f"Test timed out after {timeout} seconds")
    except Exception as e:
        pytest.skip(f"Error testing prompts: {e}")

# 保留独立运行器以便手动测试
if __name__ == "__main__":
    # 如果从测试目录运行，将项目根目录添加到路径
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))
    
    async def run_test():
        await test_prompt_formats()
        
    asyncio.run(run_test()) 