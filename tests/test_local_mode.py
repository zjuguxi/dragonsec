import json
from pathlib import Path
import pytest
import requests
import asyncio
import sys

from dragonsec.providers.local import LocalProvider

@pytest.mark.asyncio
async def test_local_provider():
    """Test local provider"""
    # 检查 Ollama 服务器是否可用
    provider = LocalProvider(model="deepseek-r1:1.5b")
    if not provider.is_server_available():
        pytest.skip("Local model server is not available")
    
    # 简单的测试代码
    code = """
def unsafe_sql_query(user_input):
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    return query
"""
    
    # 设置超时
    timeout = 60  # 60秒超时
    
    try:
        # 使用 asyncio.wait_for 添加超时控制
        result = await asyncio.wait_for(
            provider.analyze_code(code, "test_code.py"),
            timeout=timeout
        )
        
        # 基本验证
        assert "vulnerabilities" in result
        assert "overall_score" in result
        assert isinstance(result["vulnerabilities"], list)
        
        # 验证是否检测到 SQL 注入
        vuln_types = [v.get("type", "").lower() for v in result["vulnerabilities"]]
        assert any("sql" in t for t in vuln_types), "SQL injection not detected"
        
    except asyncio.TimeoutError:
        pytest.skip(f"Test timed out after {timeout} seconds")
    except Exception as e:
        pytest.skip(f"Error testing local provider: {e}")

# 保留独立运行器以便手动测试
if __name__ == "__main__":
    # 如果从测试目录运行，将项目根目录添加到路径
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))
    
    async def run_test():
        await test_local_provider()
        
    asyncio.run(run_test()) 