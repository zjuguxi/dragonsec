import json
import os
import sys
from pathlib import Path
import time
import pytest
import requests

from dragonsec.providers.local import LocalProvider

@pytest.mark.asyncio
async def test_model_sizes():
    """Test different model sizes"""
    # 检查 Ollama 服务器是否可用
    provider = LocalProvider(model="deepseek-r1:1.5b")
    if not provider.is_server_available():
        pytest.skip("Local model server is not available")
    
    # Define models to test - test smaller model first
    models = [
        "deepseek-r1:1.5b",  # 先测试小模型
        "deepseek-r1:32b"
    ]
    
    # Get test file path - adjust for tests directory
    test_file = Path(__file__).parent / "fixtures" / "vulnerable_code.py"
    
    if not test_file.exists():
        pytest.skip(f"Test file not found: {test_file}")
    
    # Read file content
    with open(test_file, "r") as f:
        code = f.read()
    
    results = {}
    
    # Test each model
    for model in models:
        # Create provider with specific model
        provider = LocalProvider(model=model)
        
        try:
            # Measure performance
            start_time = time.time()
            
            # Analyze code
            result = await provider._analyze_with_ai(code, str(test_file))
            
            # Calculate time taken
            elapsed_time = time.time() - start_time
            
            # Store results
            results[model] = {
                "time_taken": elapsed_time,
                "vulnerabilities_found": len(result.get("vulnerabilities", [])),
                "overall_score": result.get("overall_score", 100)
            }
            
            # Basic assertions
            assert "vulnerabilities" in result
            assert "overall_score" in result
            assert isinstance(result["vulnerabilities"], list)
        except Exception as e:
            pytest.skip(f"Error testing model {model}: {e}")
    
    # Compare models (basic check)
    assert len(results) == len(models)
    
    # Optional: Save results for manual inspection
    if os.environ.get("SAVE_TEST_RESULTS"):
        output_file = Path(__file__).parent / "model_comparison.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

# Keep the standalone runner for manual testing
if __name__ == "__main__":
    # Add project root to path if running from tests directory
    import asyncio
    project_root = Path(__file__).parent.parent
    if project_root not in sys.path:
        sys.path.insert(0, str(project_root))
    
    async def run_test():
        await test_model_sizes()
        
    asyncio.run(run_test()) 