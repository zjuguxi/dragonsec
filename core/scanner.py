from typing import Dict
from dragonsec.utils.semgrep import SemgrepRunner

class Scanner:
    async def scan_file(self, file_path: str) -> Dict:
        # ...
        if self.ai_provider:
            ai_results = await self.ai_provider.analyze_code(file_context)
            results.update(ai_results)  # 确保 AI 结果被合并
        # ... 