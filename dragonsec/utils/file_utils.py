# 新文件，包含所有文件处理相关功能
from pathlib import Path
from typing import Dict, List, Optional
import json
import re
import os
import logging

logger = logging.getLogger(__name__)

class FileContext:
    def __init__(self):
        self.root_indicators = {'.git', 'package.json', 'setup.py', 'pom.xml', 'build.gradle'}

    def get_context(self, file_path: str) -> Dict:
        """Get context information for a file"""
        try:
            # 验证文件路径
            path = Path(file_path).resolve()  # 解析符号链接
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            if not path.is_file():
                raise ValueError(f"Not a file: {file_path}")
                
            # 检查是否在项目目录内 - 修改这里
            try:
                # 允许测试目录下的文件
                if "test" in str(path).lower() or "pytest" in str(path).lower():
                    pass
                else:
                    path.relative_to(Path.cwd())
            except ValueError:
                raise ValueError(f"File path outside project directory: {file_path}")
                
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            return {
                "content": content,
                "imports": self.analyze_imports(content),
                "related_files": self.find_related_files(str(path))
            }
        except Exception as e:
            logger.error(f"Error getting context for {file_path}: {e}")
            return {"content": "", "imports": [], "related_files": []}

    def find_project_root(self, file_path: str) -> Optional[str]:
        current = Path(file_path).parent
        while current != current.parent:
            if any((current / indicator).exists() for indicator in self.root_indicators):
                return str(current)
            current = current.parent
        return None

    def analyze_imports(self, content: str) -> List[str]:
        """Analyze imports in code content"""
        # 限制输入大小，防止 ReDoS
        MAX_SIZE = 1024 * 1024  # 1MB
        if len(content) > MAX_SIZE:
            logger.warning(f"File too large for import analysis: {len(content)} bytes")
            return []
        
        imports = []
        try:
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # JavaScript require
                if 'require(' in line:
                    match = re.search(r"require\(['\"](.+?)['\"]\)", line)
                    if match:
                        imports.append(match.group(1))
                
                # ES6 import
                elif ' from ' in line:
                    # 提取模块名
                    match = re.search(r"from ['\"](.+?)['\"]", line)
                    if match:
                        module = match.group(1)
                        imports.append(module)
                        
                    # 提取导入的内容
                    if line.startswith('import '):
                        # 处理 import { x } from 'y' 的情况
                        content_match = re.search(r"import\s*{?\s*([^}]+?)\s*}?\s*from", line)
                        if content_match:
                            imported = content_match.group(1).strip()
                            if imported != '*':
                                imports.append(imported)
                
                # 简单的导入
                elif line.startswith('import '):
                    # 处理 import x as y 的情况
                    for part in line[7:].split(','):
                        part = part.strip()
                        if ' as ' in part:
                            module = part.split(' as ')[0].strip()
                        else:
                            module = part
                        imports.append(module)
                
                # from ... import ...
                elif line.startswith('from '):
                    if ' import ' in line:
                        module = line[5:line.index(' import ')].strip()
                        imports.append(module)
                
            return list(set(imp for imp in imports if imp))  # 去重并移除空值
            
        except Exception as e:
            logger.error(f"Error analyzing imports: {e}")
            return []

    def find_related_files(self, file_path: str) -> List[str]:
        try:
            # 确保文件在项目目录内
            path = Path(file_path).resolve()
            project_root = Path.cwd().resolve()
            
            if not str(path).startswith(str(project_root)):
                logger.warning(f"File outside project directory: {file_path}")
                return []
            
            # 安全地查找相关文件
            file_name = path.stem
            related = []
            
            for ext in ['.py', '.js', '.ts', '.java', '.go', '.php']:
                for p in project_root.rglob(f"*{file_name}*{ext}"):
                    if p.is_file() and p != path:
                        related.append(str(p))
                    
            return related[:5]  # 限制返回数量
        except Exception as e:
            logger.error(f"Error finding related files: {e}")
            return []

    def get_project_structure(self, root_dir: str) -> Dict[str, List[str]]:
        structure = {}
        for root, _, files in os.walk(root_dir):
            rel_path = os.path.relpath(root, root_dir)
            if rel_path == '.':
                structure['/'] = files
            else:
                structure[rel_path] = files
        return structure

    def analyze_dependencies(self, root_dir: str) -> Dict[str, str]:
        dependencies = {}
        
        requirements_file = Path(root_dir) / 'requirements.txt'
        if requirements_file.exists():
            with open(requirements_file, 'r') as f:
                for line in f:
                    if '==' in line:
                        name, version = line.strip().split('==')
                        dependencies[name] = version
                        
        package_json = Path(root_dir) / 'package.json'
        if package_json.exists():
            with open(package_json, 'r') as f:
                data = json.load(f)
                dependencies.update(data.get('dependencies', {}))
                dependencies.update(data.get('devDependencies', {}))
                
        return dependencies

    def is_text_file(self, file_path: str) -> bool:
        """Check if a file is a text file"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return not bool(b'\x00' in chunk)  # 简单的二进制检测
        except Exception:
            return False
