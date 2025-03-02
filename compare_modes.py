import asyncio
import json
from pathlib import Path
from dragonsec.core.scanner import SecurityScanner, ScanMode
import os

async def compare_modes():
    # 获取测试文件路径
    test_file = Path(__file__).parent / "tests" / "fixtures" / "vulnerable_code.py"
    if not test_file.exists():
        print(f"测试文件不存在: {test_file}")
        return
    
    # 定义要测试的模式
    modes = {
        ScanMode.SEMGREP_ONLY: None,
        ScanMode.LOCAL: None
    }
    
    # 如果有API密钥，添加其他模式
    if os.environ.get("OPENAI_API_KEY"):
        modes[ScanMode.OPENAI] = os.environ.get("OPENAI_API_KEY")
    
    results = {}
    
    # 对每种模式进行测试
    for mode, api_key in modes.items():
        print(f"\n测试模式: {mode.value}")
        scanner = SecurityScanner(
            mode=mode,
            api_key=api_key,
            verbose=True,
            batch_size=1,
            include_tests=True
        )
        
        result = await scanner.scan_file(str(test_file))
        results[mode.value] = result
        
        print(f"  发现漏洞数量: {len(result.get('vulnerabilities', []))}")
        print(f"  安全评分: {result.get('overall_score')}")
    
    # 保存比较结果
    with open("mode_comparison.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\n比较结果已保存到 mode_comparison.json")

if __name__ == "__main__":
    asyncio.run(compare_modes()) 