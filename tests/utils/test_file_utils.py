import pytest
from pathlib import Path
from dragonsec.utils.file_utils import FileContext
import tempfile
import os
import json
from typing import List

@pytest.fixture
def file_context():
    return FileContext()

@pytest.fixture
def sample_file_path():
    return Path(__file__).parent.parent / "fixtures" / "sample_file.py"

@pytest.fixture(scope="session")
def fixtures_dir():
    path = Path(__file__).parent / "fixtures"
    path.mkdir(parents=True, exist_ok=True)
    return path

def test_file_context_initialization():
    """测试 FileContext 初始化"""
    context = FileContext()
    assert context._scan_root is None
    assert context._allowed_paths == set()
    assert context._imports == []

def test_set_scan_root():
    """测试设置扫描根目录"""
    context = FileContext()
    test_dir = "/test/dir"
    context.set_scan_root(test_dir)
    assert str(context._scan_root) == os.path.abspath(test_dir)
    assert context._allowed_paths == {context._scan_root}

def test_add_allowed_path(tmp_path):
    """测试添加允许路径"""
    context = FileContext()
    # 使用临时目录而不是硬编码路径
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()
    context.add_allowed_path(str(test_dir))
    assert test_dir.resolve() in context._allowed_paths

def test_get_context_with_valid_file(tmp_path):
    """测试获取有效文件的上下文"""
    test_file = tmp_path / "test.py"
    test_file.write_text("""
import os
from pathlib import Path
import sys
""")
    
    context = FileContext()
    result = context.get_context(str(test_file))
    
    assert result["content"] == test_file.read_text()
    assert "os" in result["imports"]
    assert "pathlib" in result["imports"]
    assert "sys" in result["imports"]
    assert result["error"] is None

def test_get_context_with_binary_file(tmp_path):
    """测试处理二进制文件"""
    binary_file = tmp_path / "test.bin"
    with open(binary_file, 'wb') as f:
        f.write(b'\x00\x01\x02\x03')
    
    context = FileContext()
    result = context.get_context(str(binary_file))
    
    assert result["content"] == ""
    assert result["imports"] == []
    assert result["error"] is not None
    assert "Binary file" in result["error"]

def test_get_context_with_nonexistent_file(tmp_path):
    """测试处理不存在的文件"""
    context = FileContext()
    # 使用临时目录中的不存在的文件
    nonexistent_file = tmp_path / "nonexistent.py"
    result = context.get_context(str(nonexistent_file))
    assert result["content"] == ""
    assert result["imports"] == []
    assert result["error"] is not None
    # 使用更通用的错误消息检查
    assert any(msg in result["error"] for msg in ["No such file", "File not found"])

def test_find_project_root(tmp_path):
    """测试查找项目根目录"""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    (project_dir / ".git").mkdir()
    
    test_file = project_dir / "src" / "test.py"
    test_file.parent.mkdir()
    test_file.touch()
    
    context = FileContext()
    root = context.find_project_root(str(test_file))
    assert root == str(project_dir)

def test_find_related_files(tmp_path):
    """测试查找相关文件"""
    # 创建测试文件
    main_file = tmp_path / "main.py"
    main_file.write_text("from module import func")
    module_file = tmp_path / "module.py"
    module_file.write_text("def func(): pass")
    
    context = FileContext()
    # 设置扫描根目录
    context.set_scan_root(str(tmp_path))
    
    # 调试信息
    print(f"Scan root: {context._get_scan_root()}")
    print(f"Main file: {main_file}")
    print(f"Module file: {module_file}")
    
    result = context.get_context(str(main_file))
    
    # 调试信息
    print(f"Related files: {result['related_files']}")
    
    # 使用 Path 对象进行比较
    assert any(Path(f) == module_file for f in result["related_files"])

def test_analyze_imports():
    """测试导入分析"""
    context = FileContext()
    code = """
    import os
    from pathlib import Path
    from .local_module import func
    import sys as system
    from random import randint, choice
    """
    imports = context.analyze_imports(code)
    
    assert "os" in imports
    assert "pathlib" in imports
    assert ".local_module" in imports
    assert "sys" in imports
    assert "random" in imports

def test_file_context_symlink_handling(tmp_path):
    """测试符号链接处理"""
    # 在 Windows 上跳过此测试
    if os.name == 'nt':
        pytest.skip("Symbolic link test skipped on Windows")
    
    real_file = tmp_path / "real.py"
    real_file.write_text("print('test')")
    symlink = tmp_path / "link.py"
    symlink.symlink_to(real_file)
    
    context = FileContext(str(symlink))
    assert context.file_path == str(real_file)
    
    result = context.get_context(str(symlink))
    assert result["content"] == "print('test')"
    assert result["error"] is None

def test_get_project_structure(tmp_path):
    """测试获取项目结构"""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    
    # 创建项目结构
    (project_dir / "src").mkdir()
    (project_dir / "src" / "main.py").write_text("print('main')")
    (project_dir / "tests").mkdir()
    (project_dir / "tests" / "test_main.py").write_text("def test(): pass")
    
    context = FileContext()
    context.set_scan_root(str(project_dir))
    structure = context.get_project_structure(str(project_dir))
    
    assert "src" in structure
    assert "tests" in structure
    assert "main.py" in structure["src"]
    assert "test_main.py" in structure["tests"]

def test_analyze_dependencies(tmp_path):
    """测试依赖分析"""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    
    # 创建依赖文件
    (project_dir / "requirements.txt").write_text("""
requests==2.28.0
pytest==7.0.0
""")
    
    (project_dir / "package.json").write_text(json.dumps({
        "dependencies": {
            "lodash": "^4.17.21"
        },
        "devDependencies": {
            "jest": "^29.0.0"
        }
    }))
    
    context = FileContext()
    context.set_scan_root(str(project_dir))
    deps = context.analyze_dependencies(str(project_dir))
    
    assert "requests" in deps
    assert "pytest" in deps
    assert "lodash" in deps
    assert "jest" in deps

def test_get_context(sample_file_path):
    try:
        context = FileContext()
        result = context.get_context(str(sample_file_path))
        assert "content" in result
        assert "imports" in result
        assert isinstance(result["content"], str)
        assert isinstance(result["imports"], list)
    except Exception as e:
        pytest.fail(f"Test failed: {e}")

def test_get_context_with_imports(fixtures_dir):
    """Test getting file context with imports"""
    code = """
import os
from pathlib import Path
import sys
"""
    test_file = fixtures_dir / "test_imports.py"
    test_file.write_text(code.strip())  # 移除前导空格
    
    context = FileContext()
    result = context.get_context(str(test_file))
    
    assert result["imports"]  # 确保有导入
    assert "os" in result["imports"]
    assert "pathlib" in result["imports"]
    assert "sys" in result["imports"]

def test_find_project_root_with_git():
    """Test finding project root with .git directory"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create .git directory
        (tmpdir / ".git").mkdir()
        
        # Create nested file
        test_dir = tmpdir / "src" / "module"
        test_dir.mkdir(parents=True)
        test_file = test_dir / "test.py"
        test_file.touch()
        
        context = FileContext()
        root = context.find_project_root(str(test_file))
        assert root == str(tmpdir)

def test_file_context_with_large_file(tmp_path):
    """Test handling of large files"""
    large_file = tmp_path / "large.py"
    # 创建一个超过限制的大文件
    large_content = "x" * (2 * 1024 * 1024)  # 2MB
    large_file.write_text(large_content)
    
    context = FileContext()
    result = context.get_context(str(large_file))
    assert result["imports"] == []  # 大文件应该跳过导入分析

def test_file_context_with_complex_imports(tmp_path):
    """Test handling of complex import patterns"""
    test_file = tmp_path / "complex_imports.py"
    content = """
    import os, sys, json
    from pathlib import Path
    from .local_module import something
    from ..parent_module import another_thing
    import security.crypto as crypto
    from auth.utils import *
    """
    test_file.write_text(content)
    
    context = FileContext()
    result = context.get_context(str(test_file))
    assert "os" in result["imports"]
    assert "sys" in result["imports"]
    assert "pathlib" in result["imports"]
    assert "security.crypto" in result["imports"]
    assert "auth.utils" in result["imports"]

def test_file_context_with_js_imports(tmp_path):
    """Test handling of JavaScript imports"""
    test_file = tmp_path / "module.js"
    content = """
    const crypto = require('crypto');
    import { auth } from '@company/auth';
    import security from './security';
    """
    test_file.write_text(content)
    
    context = FileContext()
    result = context.get_context(str(test_file))
    assert "crypto" in result["imports"]
    assert "@company/auth" in result["imports"]
    assert "./security" in result["imports"]

def test_file_context_binary_file_handling(tmp_path):
    """Test handling of binary files"""
    # Create a binary file
    binary_file = tmp_path / "test.bin"
    with open(binary_file, 'wb') as f:
        f.write(b'\x00\x01\x02\x03')
    
    context = FileContext()
    result = context.get_context(str(binary_file))
    assert result["error"] is not None

def find_related_files(self, file_path: str) -> List[str]:
    try:
        path = Path(file_path).resolve()
        scan_root = self._get_scan_root()
        
        # 获取文件名（不含扩展名）
        file_name = path.stem
        related = []
        
        # 在扫描根目录下查找相关文件
        for ext in ['.py', '.js', '.ts', '.java', '.go', '.php']:
            # 修改匹配模式，使其更精确
            pattern = f"{file_name}{ext}"  # 精确匹配文件名
            for p in scan_root.rglob(pattern):
                if p.is_file() and p != path:
                    related.append(str(p))
                    
        return related[:5]  # 限制返回数量
    except Exception as e:
        logger.error(f"Error finding related files: {e}")
        return [] 