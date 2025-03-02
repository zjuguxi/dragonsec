"""Grok AI provider for code analysis"""

import logging
from typing import Dict, List
import json
from openai import AsyncOpenAI
from .base import AIProvider  # 从 base 导入
import os
import re

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

    def _parse_response(self, response: str, file_path: str) -> Dict:
        """Parse response from Grok API
        
        Args:
            response: Response from Grok API
            file_path: Path to the file being analyzed
            
        Returns:
            Parsed response with vulnerabilities
        """
        try:
            # 提取文件名，用于设置正确的文件名
            file_name = os.path.basename(file_path)
            
            # 尝试解析 JSON 响应
            try:
                # 查找 JSON 块
                json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                    result = json.loads(json_str)
                    
                    # 确保结果包含必要的字段
                    if not isinstance(result, dict):
                        result = {"vulnerabilities": []}
                    
                    if "vulnerabilities" not in result:
                        result["vulnerabilities"] = []
                    
                    # 修复漏洞中的文件名和行号
                    for vuln in result["vulnerabilities"]:
                        # 设置正确的文件名
                        vuln["file"] = file_name
                        
                        # 如果行号不存在或为默认值 1，尝试从描述中提取
                        if "line_number" not in vuln or vuln["line_number"] == 1:
                            # 尝试从描述中提取行号
                            line_match = re.search(r'line\s+(\d+)', vuln.get("description", ""), re.IGNORECASE)
                            if line_match:
                                vuln["line_number"] = int(line_match.group(1))
                        
                        # 确保每个漏洞都有 source 字段
                        vuln["source"] = "ai"
                    
                    # 计算整体评分
                    if "overall_score" not in result:
                        # 根据漏洞数量和严重程度计算评分
                        vulns = result["vulnerabilities"]
                        if vulns:
                            avg_severity = sum(v.get("severity", 5) for v in vulns) / len(vulns)
                            result["overall_score"] = max(0, 100 - (avg_severity * 10))
                        else:
                            result["overall_score"] = 100
                    
                    # 添加摘要
                    if "summary" not in result:
                        if result["vulnerabilities"]:
                            result["summary"] = f"Found {len(result['vulnerabilities'])} potential security issues"
                        else:
                            result["summary"] = "No security issues found"
                    
                    return result
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON response")
            
            # 如果 JSON 解析失败，尝试文本分析
            return self._analyze_text_response(response, file_path)
            
        except Exception as e:
            logger.error(f"Error parsing response: {e}")
            return {"vulnerabilities": [], "overall_score": 100, "summary": "Error parsing response"}

    def _analyze_text_response(self, response: str, file_path: str) -> Dict:
        """Analyze text response when JSON parsing fails
        
        Args:
            response: Response from Grok API
            file_path: Path to the file being analyzed
            
        Returns:
            Analyzed response with vulnerabilities
        """
        # 提取文件名，用于设置正确的文件名
        file_name = os.path.basename(file_path)
        
        result = {
            "vulnerabilities": [],
            "overall_score": 100,
            "summary": "No security issues found"
        }
        
        # 查找漏洞描述
        vuln_patterns = [
            r'(?i)vulnerability\s*(?:\d+)?\s*:\s*(.*?)(?:\n\n|\Z)',
            r'(?i)issue\s*(?:\d+)?\s*:\s*(.*?)(?:\n\n|\Z)',
            r'(?i)security\s+issue\s*(?:\d+)?\s*:\s*(.*?)(?:\n\n|\Z)',
            r'(?i)finding\s*(?:\d+)?\s*:\s*(.*?)(?:\n\n|\Z)'
        ]
        
        # 跟踪已处理的漏洞类型，避免重复
        processed_types = set()
        
        for pattern in vuln_patterns:
            for match in re.finditer(pattern, response, re.DOTALL):
                description = match.group(1).strip()
                
                # 尝试确定漏洞类型
                type_match = re.search(r'(?i)(sql\s+injection|xss|csrf|command\s+injection|path\s+traversal|insecure\s+deserialization|hardcoded\s+credentials|sensitive\s+data\s+exposure)', description)
                detected_type = type_match.group(1).lower().replace(' ', '-') if type_match else "security-issue"
                
                # 避免重复添加相同类型的漏洞
                if detected_type in processed_types:
                    continue
                
                # 尝试从描述中提取行号
                line_match = re.search(r'line\s+(\d+)', description, re.IGNORECASE)
                line_number = int(line_match.group(1)) if line_match else 1
                
                # 尝试确定严重程度
                severity = 5  # 默认中等严重程度
                if re.search(r'(?i)critical|severe|high\s+risk|high\s+severity', description):
                    severity = 9
                elif re.search(r'(?i)medium|moderate', description):
                    severity = 5
                elif re.search(r'(?i)low|minor', description):
                    severity = 3
                
                # 创建漏洞对象
                vuln = {
                    "type": detected_type,
                    "severity": severity,
                    "description": description,
                    "line_number": line_number,
                    "file": file_name,  # 使用正确的文件名
                    "source": "ai"
                }
                
                # 添加漏洞
                result["vulnerabilities"].append(vuln)
                processed_types.add(detected_type)
        
        # 更新分数和摘要
        if result["vulnerabilities"]:
            avg_severity = sum(v["severity"] for v in result["vulnerabilities"]) / len(result["vulnerabilities"])
            result["overall_score"] = max(0, 100 - (avg_severity * 10))
            result["summary"] = f"Found {len(result['vulnerabilities'])} potential issues through text analysis"
        
        return result 