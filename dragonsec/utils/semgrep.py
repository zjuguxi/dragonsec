import subprocess
import json
from pathlib import Path
from typing import Dict, List
import asyncio
import hashlib
import os
from .rule_manager import RuleManager

class SemgrepRunner:
    def __init__(self, workers: int = None, cache: Dict = None, verbose: bool = False):
        self.workers = workers
        self.cache = cache or {}
        self.verbose = verbose
        self.rule_manager = RuleManager(verbose=verbose)
        
        if self.verbose:
            print("Using Semgrep rules:")
            for rule_id, desc in self.rule_manager.rule_sets.items():
                print(f"  • {desc} ({rule_id})")

    async def run_scan(self, target_path: str) -> Dict:
        """Run semgrep scan with optimizations"""
        target_path = os.path.expanduser(target_path)
        
        # check cache
        file_hash = self._get_file_hash(target_path)
        if file_hash in self.cache:
            return self.cache[file_hash]

        rules = self.rule_manager.get_rules_for_file(target_path)
        rule_args = []
        for rule in rules:
            rule_args.extend(["--config", rule])

        cmd = [
            "semgrep", "scan",
            *rule_args,
            "--json",
            "--timeout", "30",
            "--timeout-threshold", "3",
            f"--jobs", str(self.workers),
            "--max-memory", "0",
            "--optimizations", "all",
            "--exclude", "node_modules,build,dist,*.min.js,venv",
            target_path
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout_bytes, stderr_bytes = await process.communicate()
            stdout = stdout_bytes.decode('utf-8')
            stderr = stderr_bytes.decode('utf-8')

            if process.returncode == 0:
                try:
                    parsed_result = json.loads(stdout)
                    if self.verbose:
                        print(f"Semgrep raw output for {target_path}:")
                        print(json.dumps(parsed_result, indent=2))
                    self.cache[file_hash] = parsed_result
                    return parsed_result
                except json.JSONDecodeError:
                    print("❌ Failed to parse Semgrep JSON output")
                    return {"results": []}
            else:
                if stderr and "No files were analyzed" not in stderr:
                    print(f"❌ Semgrep execution failed: {stderr}")
                return {"results": []}
        except Exception as e:
            print(f"Error running semgrep: {e}")
            return {"results": []}

    def _get_file_hash(self, file_path: str) -> str:
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return file_path

    def format_results(self, results: Dict) -> List[Dict]:
        """Format semgrep results"""
        if not results or "results" not in results:
            return []

        vulnerabilities = []
        for finding in results.get("results", []):
            if not finding or not finding.get("check_id"):
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
            
            if vuln["type"] != "unknown" and vuln["description"]:
                vulnerabilities.append(vuln)
            
        return vulnerabilities

    def _convert_severity(self, severity: str) -> int:
        """Convert semgrep severity to numeric scale"""
        severity_map = {
            "ERROR": 9,
            "WARNING": 6,
            "INFO": 3,
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 2
        }
        return severity_map.get(severity.lower(), 5) 