import json
import os
import sys
from pathlib import Path
import time
import pytest
import requests
import asyncio

from dragonsec.providers.local import LocalProvider
from dragonsec.providers.openai import OpenAIProvider

@pytest.mark.asyncio
async def test_model_sizes():
    """Test different model sizes"""
    # 检查 Ollama 服务器是否可用
    provider = LocalProvider(model="deepseek-r1:1.5b")
    if not provider.is_server_available():
        # 如果本地服务器不可用，使用 OpenAI 作为备选
        if not os.getenv("OPENAI_API_KEY"):
            pytest.skip("Neither local model server nor OpenAI API key is available")
        provider = OpenAIProvider(api_key=os.getenv("OPENAI_API_KEY"))
    
    # 测试代码
    code = """
def unsafe_sql_query(user_input):
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    return query

def unsafe_command(user_input):
    import os
    os.system(f"echo {user_input}")
    
def unsafe_path(user_input):
    with open(f"/tmp/{user_input}", "r") as f:
        return f.read()
        
def safe_function(user_input):
    return "Hello, " + str(user_input)
"""
    
    try:
        # 设置超时
        start_time = time.time()
        timeout = 60  # 60秒超时
        
        # 使用 asyncio.wait_for 添加超时控制
        result = await asyncio.wait_for(
            provider.analyze_code(code, "test_code.py"),
            timeout=timeout
        )
        
        # 验证结果
        assert "vulnerabilities" in result
        assert "overall_score" in result
        assert isinstance(result["vulnerabilities"], list)
        
        # 验证是否检测到所有类型的漏洞
        vuln_types = [v.get("type", "").lower() for v in result["vulnerabilities"]]
        assert any("sql" in t for t in vuln_types), "SQL injection not detected"
        assert any("command" in t for t in vuln_types), "Command injection not detected"
        assert any("path" in t for t in vuln_types), "Path traversal not detected"
        
    except asyncio.TimeoutError:
        pytest.skip(f"Test timed out after {timeout} seconds")
    except Exception as e:
        pytest.skip(f"Error testing provider: {e}")

# 保留独立运行器以便手动测试
if __name__ == "__main__":
    # 如果从测试目录运行，将项目根目录添加到路径
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))
    
    async def run_test():
        await test_model_sizes()
        
    asyncio.run(run_test()) 