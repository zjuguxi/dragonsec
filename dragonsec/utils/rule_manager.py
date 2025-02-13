import os
import json
import time
from pathlib import Path
from typing import List, Dict
import shutil
import requests
from datetime import datetime, timedelta
import subprocess

class RuleManager:
    """Manages Semgrep rule sets selection"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose  # 添加 verbose 属性
        # Rule set configurations
        self.rule_sets = {
            "p/owasp-top-ten": "OWASP Top 10",
            "p/ci": "CI/CD Security",
            "p/supply-chain": "Supply Chain Security",
            "p/jwt": "JWT Security",
            "p/secrets": "Secrets Detection",
            "p/golang": "Go Security",
            "p/python": "Python Security",
            "p/javascript": "JavaScript Security",
            "p/java": "Java Security",
            "p/docker": "Docker Security",
            "p/kubernetes": "Kubernetes Security"
        }

    def get_rules_for_file(self, file_path: str) -> List[str]:
        """Get relevant rules based on file type"""
        file_ext = Path(file_path).suffix.lower()
        file_name = Path(file_path).name.lower()
        
        # 基础规则集 - 只保留最重要的
        base_rules = [
            "p/secrets",  # 敏感信息检查
        ]
        
        # 根据文件类型添加特定规则
        ext_rules = {
            # Python 文件
            '.py': ["p/python", "p/owasp-top-ten"],
            
            # JavaScript/TypeScript 文件
            '.js': ["p/javascript", "p/owasp-top-ten"],
            '.ts': ["p/javascript", "p/owasp-top-ten"],
            
            # Java 文件
            '.java': ["p/java", "p/owasp-top-ten"],
            
            # Go 文件
            '.go': ["p/golang", "p/owasp-top-ten"],
            
            # 配置文件
            'dockerfile': ["p/docker"],
            '.yaml': ["p/kubernetes"],
            '.yml': ["p/kubernetes"]
        }
        
        # 获取文件特定的规则
        specific_rules = ext_rules.get(file_ext, [])
        if self.verbose:
            print(f"Selected rules for {file_path}: {base_rules + specific_rules}")
        
        return base_rules + specific_rules

    def get_enabled_rules(self) -> List[str]:
        """Get list of all available rule sets"""
        return list(self.rule_sets.keys())

    def get_rule_description(self, rule_id: str) -> str:
        """Get description for a rule set"""
        return self.rule_sets.get(rule_id, "Unknown rule set") 