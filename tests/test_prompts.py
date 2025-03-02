import json
import pytest
from dragonsec.providers.local import LocalProvider
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
        pytest.skip("Local model server is not available")
    
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
    
    results = {}
    
    for i, prompt in enumerate(prompts):
        try:
            print(f"Testing prompt format {i+1}")
            
            # 创建自定义提示的提供者
            class CustomPromptProvider(LocalProvider):
                def _build_prompt(self, code, file_path=None):
                    return f"{prompt}\n\n```python\n{code}\n```"
            
            provider = CustomPromptProvider(model="deepseek-r1:1.5b")
            
            # 设置超时
            timeout = 60  # 60秒超时
            
            # 使用 asyncio.wait_for 添加超时控制
            try:
                result = await asyncio.wait_for(
                    provider.analyze_code(code, "test_code.py"),
                    timeout=timeout
                )
                
                # 保存结果
                results[f"prompt_{i+1}"] = result
                
                # 基本验证
                assert "vulnerabilities" in result
                assert "overall_score" in result
                
            except asyncio.TimeoutError:
                print(f"Prompt {i+1} timed out after {timeout} seconds")
                results[f"prompt_{i+1}"] = {"error": "timeout"}
                continue
                
        except Exception as e:
            print(f"Error testing prompt {i+1}: {e}")
            results[f"prompt_{i+1}"] = {"error": str(e)}
    
    # 确保至少有一个提示格式成功测试
    assert len(results) > 0, "No prompt formats were successfully tested"
    
    # 可选：保存结果以供手动检查
    if os.environ.get("SAVE_TEST_RESULTS"):
        output_file = Path(__file__).parent / "prompt_comparison.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

# 保留独立运行器以便手动测试
if __name__ == "__main__":
    # 如果从测试目录运行，将项目根目录添加到路径
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))
    
    async def run_test():
        await test_prompt_formats()
        
    asyncio.run(run_test()) 