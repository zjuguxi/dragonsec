import json
from pathlib import Path
from typing import Dict, List
import asyncio
import hashlib
import os
import logging
from .rule_manager import RuleManager

# 配置 logger
logger = logging.getLogger(__name__)

class SemgrepRunner:
    def __init__(self, workers: int = None, cache: Dict = None):
        self.workers = workers or os.cpu_count()
        self.cache = cache or {}
        self.rule_manager = RuleManager()
        
        # 配置日志级别
        if os.getenv('DRAGONSEC_DEBUG'):
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
        
    def _parse_semgrep_output(self, output: str) -> Dict:
        """Parse semgrep output into structured format"""
        try:
            results = json.loads(output)
            findings = []
            
            for result in results.get("results", []):
                # 提取基本信息
                path = result.get("path", "")
                
                # 获取代码片段
                start_line = result.get("start", {}).get("line", 0)
                end_line = result.get("end", {}).get("line", 0)
                lines = result.get("extra", {}).get("lines", "")
                
                # 获取规则信息
                rule_id = result.get("check_id", "")
                rule = self.rule_manager.get_rule_details(rule_id)
                
                finding = {
                    "path": path,
                    "check_id": rule_id,
                    "start": {"line": start_line},
                    "end": {"line": end_line},
                    "lines": lines,
                    "extra": {
                        "severity": rule.get("severity", "medium"),
                        "message": result.get("extra", {}).get("message") or rule.get("message", ""),
                        "metadata": {
                            "cwe": rule.get("cwe"),
                            "owasp": rule.get("owasp"),
                            "impact": rule.get("impact", "This issue could pose a security risk"),
                            "fix": rule.get("fix", "Review and fix according to secure coding guidelines")
                        },
                        "fix": rule.get("fix_description", ""),
                        "references": rule.get("references", [])
                    }
                }
                
                # 添加详细的代码上下文
                if lines:
                    finding["extra"]["code_snippet"] = {
                        "code": lines,
                        "start_line": start_line,
                        "end_line": end_line
                    }
                
                findings.append(finding)
                
            return {"results": findings}
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse semgrep output: {e}")
            return {"results": []}
            
        except Exception as e:
            logger.error(f"Error processing semgrep results: {e}")
            return {"results": []}

    async def run_scan(self, target_path: str) -> Dict:
        """Run semgrep scan with optimizations"""
        target_path = os.path.abspath(os.path.expanduser(target_path))
        
        # 验证路径
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Path does not exist: {target_path}")
        if not os.access(target_path, os.R_OK):
            raise PermissionError(f"Cannot read path: {target_path}")
        
        # 检查缓存
        file_hash = self._get_file_hash(target_path)
        if file_hash in self.cache:
            return self.cache[file_hash]

        # 只获取文件类型相关的规则
        rules = self.rule_manager.get_rules_for_file(target_path)
        
        # 优化 semgrep 命令参数
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--timeout", "60",  # 增加单个规则的超时时间到 60 秒
            "--timeout-threshold", "3",  # 允许更多规则超时
            "--jobs", str(min(2, self.workers)),  # 限制并行数
            "--max-memory", "512",  # 内存限制（MB）
            "--optimizations", "all",
            "--exclude", "node_modules,build,dist,*.min.js,venv",
            "--skip-unknown-extensions",
            "--max-target-bytes", "1000000",
            "--no-git-ignore",
            "--no-rewrite-rule-ids"
        ]
        
        # 只添加相关的规则
        for rule in rules:
            if not isinstance(rule, str) or '..' in rule:
                continue
            cmd.extend(["--config", rule])
        
        cmd.append(target_path)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # 设置整体超时时间为 120 秒
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=120.0  # 增加整体超时时间到 120 秒
                )
                stdout = stdout_bytes.decode('utf-8')
                stderr = stderr_bytes.decode('utf-8')
            except asyncio.TimeoutError:
                try:
                    process.kill()
                except:
                    pass
                logger.warning(f"Semgrep scan timed out for {target_path}")
                return {"results": []}

            if process.returncode == 0:
                try:
                    parsed_result = self._parse_semgrep_output(stdout)
                    self.cache[file_hash] = parsed_result
                    return parsed_result
                except json.JSONDecodeError:
                    logger.error("Failed to parse Semgrep JSON output")
                    return {"results": []}
            else:
                if stderr and "No files were analyzed" not in stderr:
                    logger.error(f"Semgrep execution failed: {stderr}")
                return {"results": []}
                
        except Exception as e:
            logger.error(f"Error running semgrep: {e}")
            return {"results": []}

    def _get_file_hash(self, file_path: str) -> str:
        """Get secure hash of file contents"""
        try:
            with open(file_path, 'rb') as f:
                # 使用 SHA-256 替代 MD5
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return file_path

    def format_results(self, results: Dict) -> List[Dict]:
        """Format semgrep results"""
        if not results or "results" not in results:
            return []

        vulnerabilities = []
        for finding in results.get("results", []):
            if not finding:
                continue
            
            vuln = {
                "source": "semgrep",
                "type": finding.get("check_id", "unknown"),
                "severity": self._convert_severity(finding.get("extra", {}).get("severity", "medium")),
                "description": finding.get("extra", {}).get("message", ""),
                "line_number": finding.get("start", {}).get("line", 0),
                "file": finding.get("path", ""),
                "risk_analysis": finding.get("extra", {}).get("metadata", {}).get("impact", "Unknown impact"),
                "recommendation": finding.get("extra", {}).get("metadata", {}).get("fix", "No fix provided")
            }
            
            vulnerabilities.append(vuln)
            
        return vulnerabilities

    def _convert_severity(self, severity: str) -> int:
        """Convert semgrep severity to numeric scale"""
        severity_map = {
            "error": 9,
            "warning": 6,
            "info": 3,
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 2
        }
        return severity_map.get(severity.lower(), 5) 