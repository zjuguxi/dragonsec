import json
import os
import sys
from pathlib import Path
import time
import pytest
import requests
import asyncio

from dragonsec.providers.local import LocalProvider

@pytest.mark.asyncio
async def test_model_sizes():
    """Test different model sizes"""
    # 检查 Ollama 服务器是否可用
    provider = LocalProvider(model="deepseek-r1:1.5b")
    if not provider.is_server_available():
        pytest.skip("Local model server is not available")
    
    # 只测试一个小模型，避免长时间运行
    models = ["deepseek-r1:1.5b"]  # 只使用最小的模型进行测试
    
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
    
    results = {}
    
    for model in models:
        try:
            print(f"Testing model: {model}")
            provider = LocalProvider(model=model)
            
            # 设置超时
            start_time = time.time()
            timeout = 60  # 60秒超时
            
            # 使用 asyncio.wait_for 添加超时控制
            try:
                result = await asyncio.wait_for(
                    provider.analyze_code(code, "vulnerable_code.py"),
                    timeout=timeout
                )
                
                # 记录运行时间
                elapsed = time.time() - start_time
                print(f"Model {model} took {elapsed:.2f} seconds")
                
                # 保存结果
                results[model] = {
                    "result": result,
                    "time": elapsed
                }
                
                # 基本验证
                assert "vulnerabilities" in result
                assert "overall_score" in result
                assert isinstance(result["vulnerabilities"], list)
                
                # 验证是否检测到预期漏洞
                vuln_types = [v.get("type", "").lower() for v in result["vulnerabilities"]]
                assert any("sql" in t for t in vuln_types), "SQL injection not detected"
                assert any("command" in t for t in vuln_types), "Command injection not detected"
                assert any("path" in t for t in vuln_types), "Path traversal not detected"
                
            except asyncio.TimeoutError:
                print(f"Model {model} timed out after {timeout} seconds")
                results[model] = {"error": "timeout"}
                continue
                
        except Exception as e:
            print(f"Error testing model {model}: {e}")
            results[model] = {"error": str(e)}
    
    # 确保至少有一个模型成功测试
    assert len(results) > 0, "No models were successfully tested"
    assert any("result" in v for v in results.values()), "All model tests failed"
    
    # 可选：保存结果以供手动检查
    if os.environ.get("SAVE_TEST_RESULTS"):
        output_file = Path(__file__).parent / "model_comparison.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

# 保留独立运行器以便手动测试
if __name__ == "__main__":
    # 如果从测试目录运行，将项目根目录添加到路径
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))
    
    async def run_test():
        await test_model_sizes()
        
    asyncio.run(run_test()) 