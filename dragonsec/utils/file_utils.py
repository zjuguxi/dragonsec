# 新文件，包含所有文件处理相关功能
from pathlib import Path
from typing import Dict, List, Optional
import json
import re
import os
import logging

logger = logging.getLogger(__name__)

class FileContext:
    """File context manager for security scanning"""
    
    def __init__(self, file_path: str = None):
        self.root_indicators = {'.git', 'package.json', 'setup.py', 'pom.xml', 'build.gradle'}
        self._scan_root = None
        self._allowed_paths = set()
        self._imports = []  # 添加导入列表
        self.file_path = file_path  # 添加文件路径属性
        
        if file_path:
            # 如果提供了文件路径，设置扫描根目录
            path = Path(file_path).resolve()
            self.set_scan_root(str(path.parent))
            # 添加文件所在目录到允许列表
            self.add_allowed_path(str(path.parent))

    def set_scan_root(self, path: str) -> None:
        """设置扫描根目录"""
        self._scan_root = Path(os.path.abspath(os.path.expanduser(path))).resolve()
        self._allowed_paths = {self._scan_root}  # 重置允许的路径
        
    def add_allowed_path(self, path: str) -> None:
        """添加额外的允许路径"""
        abs_path = Path(os.path.abspath(os.path.expanduser(path))).resolve()
        self._allowed_paths.add(abs_path)
    
    def _is_path_allowed(self, path: Path) -> bool:
        """检查路径是否在允许的范围内"""
        try:
            # 先检查是否是符号链接
            if path.is_symlink():
                logger.warning(f"Symlink detected: {path}")
                return False
            
            path = path.resolve()
            
            # 检查文件权限
            if os.access(path, os.W_OK):
                logger.debug(f"File is writable: {path}")
            
            # 使用 os.path.commonpath 进行更严格的路径检查
            for allowed_path in self._allowed_paths:
                allowed_path = allowed_path.resolve()
                try:
                    common = os.path.commonpath([str(path), str(allowed_path)])
                    if common == str(allowed_path):
                        return True
                except ValueError:
                    continue
            
            logger.warning(f"Path not in allowed directories: {path}")
            return False
            
        except Exception as e:
            logger.error(f"Error checking path: {e}")
            return False
    
    def get_context(self, file_path: str) -> Dict:
        """Get context information for a file"""
        try:
            path = Path(file_path).resolve()
            
            # 如果没有设置扫描根目录，使用文件所在目录
            if not self._scan_root:
                self.set_scan_root(str(path.parent))
            
            # 检查路径是否在允许的范围内
            if not self._is_path_allowed(path):
                # 自动添加文件所在目录到允许列表
                self.add_allowed_path(str(path.parent))
            
            # 检查是否是二进制文件
            try:
                with open(path, 'rb') as f:
                    is_binary = b'\0' in f.read(1024)
                    if is_binary:
                        return {
                            "content": "",
                            "imports": [],
                            "related_files": [],
                            "error": "Binary file detected"
                        }
            except Exception as e:
                return self._get_error_response(f"Error reading file: {e}")
            
            # 读取文本内容
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                return {
                    "content": "",
                    "imports": [],
                    "related_files": [],
                    "error": "Binary or non-UTF8 file detected"
                }
            
            # 分析导入
            imports = self.analyze_imports(content)
            
            return {
                "content": content,
                "imports": imports,
                "related_files": self.find_related_files(str(path)),
                "error": None
            }
            
        except Exception as e:
            logger.error(f"Error getting context for {file_path}: {e}")
            return {
                "content": "",
                "imports": [],
                "related_files": [],
                "error": str(e)
            }

    def _get_scan_root(self) -> Path:
        """获取扫描根目录"""
        if self._scan_root is None:
            return Path(os.getenv('DRAGONSEC_SCAN_ROOT', Path.cwd())).resolve()
        return Path(self._scan_root).resolve()

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
            path = Path(file_path).resolve()
            scan_root = self._get_scan_root()
            
            # 不再检查是否在项目目录内，而是使用扫描根目录
            file_name = path.stem
            related = []
            
            # 只在扫描根目录下查找相关文件
            for ext in ['.py', '.js', '.ts', '.java', '.go', '.php']:
                for p in scan_root.rglob(f"*{file_name}*{ext}"):
                    if p.is_file() and p != path:
                        related.append(str(p))
                        
            return related[:5]  # 限制返回数量
        except Exception as e:
            logger.error(f"Error finding related files: {e}")
            return []

    def get_project_structure(self, root_dir: str) -> Dict[str, List[str]]:
        # 使用扫描根目录
        scan_root = self._get_scan_root()
        structure = {}
        
        for root, _, files in os.walk(scan_root):
            rel_path = os.path.relpath(root, scan_root)
            if rel_path == '.':
                structure['/'] = files
            else:
                structure[rel_path] = files
        return structure

    def analyze_dependencies(self, root_dir: str) -> Dict[str, str]:
        # 使用扫描根目录
        scan_root = self._get_scan_root()
        dependencies = {}
        
        # 检查依赖文件
        requirements_file = scan_root / 'requirements.txt'
        if requirements_file.exists():
            with open(requirements_file, 'r') as f:
                for line in f:
                    if '==' in line:
                        name, version = line.strip().split('==')
                        dependencies[name] = version
                        
        package_json = scan_root / 'package.json'
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

    def is_file_in_scan_root(self, file_path: str, scan_root: str) -> bool:
        """检查文件是否在扫描根目录内"""
        try:
            # 规范化路径
            file_path = os.path.abspath(file_path)
            scan_root = os.path.abspath(scan_root)
            
            # 检查文件路径是否以扫描根目录开头
            return file_path.startswith(scan_root)
        except Exception as e:
            logger.error(f"Error checking file path: {e}")
            return False

    def _get_error_response(self, error_msg: str) -> Dict:
        """统一的错误响应格式"""
        return {
            "content": "",
            "imports": [],
            "related_files": [],
            "error": error_msg
        }
