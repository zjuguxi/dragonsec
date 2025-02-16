import pytest
from pathlib import Path
from dragonsec.utils.file_utils import FileContext
import tempfile

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

def test_analyze_imports(file_context):
    code = """
    import os
    from crypto.cipher import AES
    import security.auth
    from random import randint
    """
    imports = file_context.analyze_imports(code)
    assert "crypto.cipher" in imports
    assert "security.auth" in imports
    assert "random" in imports

def test_find_project_root(file_context, tmp_path):
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    (project_dir / ".git").mkdir()
    
    test_file = project_dir / "src" / "test.py"
    test_file.parent.mkdir()
    test_file.touch()
    
    root = file_context.find_project_root(str(test_file))
    assert root == str(project_dir)

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