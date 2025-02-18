"""Grok AI provider for code analysis"""

import logging
from typing import Dict, List
import json
from openai import AsyncOpenAI
from .base import AIProvider  # 从 base 导入

logger = logging.getLogger(__name__)

class GrokProvider(AIProvider):
    """Grok AI provider for code analysis"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://api.x.ai/v1"
        )
        self.model = "grok-2-latest"

    @property
    def system_prompt(self) -> str:
        """Get Grok-specific system prompt"""
        # 如果需要添加 Grok 特定的指令
        return self.base_system_prompt + """
        Additional Grok-specific instructions:
        - Use JSON response format
        - Be concise in descriptions
        """

    async def _analyze_with_ai(self, code: str, file_path: str, context: Dict = None) -> Dict:
        """Analyze code using Grok API"""
        try:
            # 构建提示
            prompt = f"""
            Analyze this code for security vulnerabilities and respond in JSON format only:
            
            File: {file_path}
            
            {code}
            """
            
            # 调用 API
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,  # 降低温度以获得更一致的输出
                max_tokens=2000,
                response_format={"type": "json_object"}  # 强制 JSON 响应
            )
            
            # 检查响应是否为空
            if not response.choices or not response.choices[0].message.content:
                logger.error("Empty response from Grok API")
                return self._get_default_response()
            
            # 解析响应
            try:
                content = response.choices[0].message.content.strip()
                logger.debug(f"Raw response content: {content}")
                
                # 尝试清理响应内容
                if content.startswith("```json"):
                    content = content.split("```json")[1]
                if content.endswith("```"):
                    content = content.rsplit("```", 1)[0]
                content = content.strip()
                
                try:
                    result = json.loads(content)
                    if not isinstance(result, dict):
                        raise ValueError("Response is not a dictionary")
                    
                    # 确保有 vulnerabilities 字段
                    if "vulnerabilities" not in result:
                        result = {"vulnerabilities": []}
                    
                    # 标准化结果
                    for vuln in result["vulnerabilities"]:
                        vuln["file"] = file_path
                        # 确保所有必需字段都存在
                        for field in ["type", "severity", "description", "line_number", "risk_analysis", "recommendation", "confidence"]:
                            if field not in vuln:
                                if field == "severity":
                                    vuln[field] = 5  # 默认中等严重性
                                else:
                                    vuln[field] = "Not provided"
                    
                    return result
                    
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {e}")
                    logger.debug(f"Failed content: {content}")
                    return self._get_default_response()
                
            except Exception as e:
                logger.error(f"Error processing response: {e}")
                logger.debug(f"Response object: {response}")
                return self._get_default_response()
            
        except Exception as e:
            logger.error(f"Error calling Grok API: {e}")
            return self._get_default_response()
    
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate security score based on vulnerabilities"""
        if not vulnerabilities:
            return 100.0
        # 使用最高严重性作为基准
        max_severity = max(v.get("severity", 0) for v in vulnerabilities)
        return max(0, 100 - (max_severity * 10))

    def merge_results(self, semgrep_results: List[Dict], ai_results: Dict) -> Dict:
        """Merge semgrep and AI results"""
        all_vulns = []
        
        # 添加 semgrep 结果
        for vuln in semgrep_results:
            all_vulns.append(vuln)
        
        # 添加 AI 结果
        if "vulnerabilities" in ai_results:
            all_vulns.extend(ai_results["vulnerabilities"])
        
        # 计算总体分数
        score = self._calculate_security_score(all_vulns)
        
        return {
            "vulnerabilities": all_vulns,
            "overall_score": score,
            "summary": f"Found {len(all_vulns)} vulnerabilities ({len(semgrep_results)} from semgrep, {len(ai_results.get('vulnerabilities', []))} from AI analysis). Security Score: {score}%"
        }

    async def deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """使用基类的去重逻辑"""
        return await super().deduplicate_vulnerabilities(vulnerabilities) 