from setuptools import setup, find_packages
from pathlib import Path

# Read README.md safely
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="dragonsec",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "semgrep>=1.107.0",
        "openai>=1.0.0",
        "google-generativeai>=0.3.0",
        "tqdm>=4.65.0",
        "tenacity>=8.0.0"
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-asyncio>=0.21.0',
            'black>=22.0.0',
            'flake8>=4.0.0',
            'mypy>=1.0.0',
        ]
    },
    entry_points={
        "console_scripts": [
            "dragonsec-scan=dragonsec.core.scanner:main",
        ],
    },
    author="Xi Gu",
    description="A security scanner combining semgrep with AI analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zjuguxi/dragonsec",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
) 