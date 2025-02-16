import subprocess
import json
import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import asyncio
from tqdm import tqdm
import time
from enum import Enum
import hashlib
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

from ..providers.base import AIProvider
from ..providers.openai import OpenAIProvider
from ..providers.gemini import GeminiProvider
from dragonsec.utils.semgrep import SemgrepRunner
from ..utils.file_utils import FileContext
from ..utils.rule_manager import RuleManager

class ScanMode(Enum):
    SEMGREP_ONLY = "semgrep"
    OPENAI = "openai"
    GEMINI = "gemini"

class SecurityScanner:
    def __init__(self, mode: ScanMode = ScanMode.SEMGREP_ONLY, api_key: str = None, 
                 workers: int = os.cpu_count(), cache: Dict = None, verbose: bool = False,
                 include_tests: bool = False, batch_size: int = 10, batch_delay: float = 2.0,
                 incremental: bool = False):
        self.mode = mode
        self.ai_provider = None
        if mode != ScanMode.SEMGREP_ONLY and api_key:
            self.ai_provider = self._create_provider(mode, api_key)
        self.semgrep_runner = SemgrepRunner(workers=workers, cache=cache)
        self.file_context = FileContext()
        self.verbose = verbose and os.getenv('DRAGONSEC_ENV') != 'production'  # 在生产环境中禁用 verbose
        self.include_tests = include_tests
        self.batch_size = batch_size
        self.batch_delay = batch_delay
        self.incremental = incremental
        config_dir = Path.home() / ".dragonsec"
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)  # 设置安全的权限
        self.last_scan_file = config_dir / "last_scan.json"
        # Define patterns for test-related files
        self.test_dir_patterns = {'tests', 'test', '__tests__', '__test__'}
        self.test_file_patterns = {'test_', '_test', 'tests.', '.test.', 'spec.', '.spec.'}
        self.workers = workers
        
        # 定义要跳过的目录
        self.skip_dirs = {
            'node_modules', 'build', 'dist', 'venv', 
            '__pycache__', '.git', '.svn', '.hg',
            'htmlcov'  # 添加 htmlcov 目录
        }
        
        # 定义要跳过的文件模式
        self.skip_files = {
            '*.min.js', '*.pyc', '*.pyo', '*.pyd',
            '*.so', '*.dylib', '*.dll', '*.coverage'
        }

    def _create_provider(self, mode: ScanMode, api_key: str) -> AIProvider:
        providers = {
            ScanMode.OPENAI: OpenAIProvider,
            ScanMode.GEMINI: GeminiProvider
        }
        return providers[mode](api_key)

    def _is_test_directory(self, path: str) -> bool:
        """Check if a directory is a test directory"""
        path_parts = Path(path).parts
        # 只检查目录名本身，不检查父目录
        return Path(path).name.lower() in self.test_dir_patterns

    def _is_test_file(self, filename: str) -> bool:
        """Check if a file is a test file"""
        filename = filename.lower()
        return any(pattern in filename for pattern in self.test_file_patterns)

    def _should_skip_path(self, path: str, is_dir: bool = True) -> bool:
        """Determine if a path should be skipped"""
        if self.include_tests or os.getenv('PYTEST_CURRENT_TEST'):
            return False
        
        path_lower = str(path).lower()
        
        # 直接使用字符串分割，更可靠
        path_parts = path_lower.split(os.sep)
        if '/' in path_lower:  # 处理正斜杠
            path_parts = path_lower.split('/')
        
        # 首先检查路径中是否包含测试目录
        for part in path_parts:
            if any(pattern in part for pattern in self.test_dir_patterns):
                return True
        
        # 如果是文件，还需要检查文件名是否匹配测试模式
        if not is_dir:
            file_name = path_parts[-1]
            return any(pattern in file_name for pattern in self.test_file_patterns)
        
        return False

    def _should_skip_file(self, file_path: str) -> bool:
        """检查是否应该跳过文件"""
        # 检查文件大小
        if os.path.getsize(file_path) == 0:
            return True
        
        # 检查文件扩展名
        if not (Path(file_path).suffix.lower() in {'.py', '.js', '.ts', '.java', '.go', '.php'} or 
                'dockerfile' in Path(file_path).name.lower()):
            return True
        
        # 检查是否是测试文件
        if not self.include_tests and self._should_skip_path(file_path, is_dir=False):
            return True
        
        return False

    async def scan_file(self, file_path: str) -> Dict:
        """Scan a single file"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"No such file: {file_path}")
        
        # 1. Run semgrep scan
        semgrep_results = await self.semgrep_runner.run_scan(file_path)
        
        # If no AI provider is configured, return semgrep results
        if not self.ai_provider:
            return {"vulnerabilities": self.semgrep_runner.format_results(semgrep_results)}
            
        # 2. Run AI analysis
        try:
            file_context = self.file_context.get_context(file_path)
            ai_results = await self.ai_provider.analyze_code(
                code=file_context["content"],
                file_path=file_path,
                context=file_context
            )
            
            # 3. Merge results
            return self.ai_provider.merge_results(
                self.semgrep_runner.format_results(semgrep_results),
                ai_results
            )
        except UnicodeDecodeError:
            print(f"Warning: Could not read {file_path} as text file, skipping AI analysis")
            return {"vulnerabilities": self.semgrep_runner.format_results(semgrep_results)}

    async def process_batch(self, files: List[str]) -> List[Dict]:
        """Process a batch of files in parallel"""
        tasks = [self.scan_file(f) for f in files]
        return await asyncio.gather(*tasks)

    async def scan_directory(self, path: str) -> Dict:
        """Scan a directory for security issues"""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Directory does not exist: {path}")
        
        # 添加开始时间
        start_time = time.time()
        
        print("\n📂 Collecting files to scan...")
        
        # 添加跳过文件计数
        skipped_files = 0
        files_to_scan = []
        for root, dirs, files in os.walk(path):
            # 跳过指定目录
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]
            
            # 跳过测试目录
            if not self.include_tests and self._should_skip_path(root, is_dir=True):
                if self.verbose:
                    print(f"Skipping test directory: {root}")
                continue
            
            if self.verbose:
                print(f"Walking directory: {root}")
                print(f"  Subdirectories after filtering: {dirs}")
                print(f"  Files: {files}")
            
            for file in files:
                file_path = os.path.join(root, file)
                abs_path = os.path.abspath(file_path)
                
                if self._should_skip_file(abs_path):
                    skipped_files += 1  # 增加计数
                    if self.verbose:
                        print(f"Skipping file: {file_path}")
                    continue
                
                if self.verbose:
                    print(f"\nProcessing file: {file_path}")
                    print(f"  Absolute path: {abs_path}")
                    print(f"  Exists: {os.path.exists(abs_path)}")
                    print(f"  Is file: {os.path.isfile(abs_path)}")
                    print(f"  Readable: {os.access(abs_path, os.R_OK)}")
                
                if self.verbose:
                    print(f"Checking file: {file_path}")
                    print(f"  name: {Path(file_path).name}")
                    print(f"  ext: {Path(file_path).suffix}")
                    print(f"  supported_ext: {Path(file_path).suffix.lower() in {'.py', '.js', '.ts', '.java', '.go', '.php'}}")
                    print(f"  is_dockerfile: {'dockerfile' in Path(file_path).name.lower()}")

                # 检查是否是 Dockerfile 或支持的扩展名
                if not (Path(file_path).suffix.lower() in {'.py', '.js', '.ts', '.java', '.go', '.php'} or 'dockerfile' in Path(file_path).name.lower()):
                    if self.verbose:
                        print(f"  Skipping unsupported file: {file_path}")
                    continue
                    
                # 跳过测试文件
                if not self.include_tests and self._should_skip_path(file_path, is_dir=False):
                    if self.verbose:
                        print(f"Skipping test file: {file_path}")
                    continue
                
                if self.verbose:
                    print(f"  Added file to scan: {file_path}")
                files_to_scan.append(file_path)
        
        # 增量扫描
        if self.incremental:
            changed_files = self._get_changed_files(files_to_scan)
            if changed_files is not None:
                files_to_scan = changed_files
        
        print(f"\n🔍 Found {len(files_to_scan)} files to scan")
        
        if not files_to_scan:
            return {
                "vulnerabilities": [],
                "overall_score": 100,
                "summary": "No files to scan",
                "metadata": {
                    "files_scanned": 0,
                    "skipped_files": skipped_files,
                    "scan_time": 0
                }
            }

        # Process files in batches
        all_vulnerabilities = []  # Use a list to store all vulnerabilities
        semgrep_count = 0
        ai_count = 0
        
        with tqdm(total=len(files_to_scan), desc="Scanning files") as pbar:
            for i in range(0, len(files_to_scan), self.batch_size):
                batch = files_to_scan[i:i + self.batch_size]
                batch_results = await self.process_batch(batch)
                
                # Merge results from each file
                for result in batch_results:
                    if "vulnerabilities" in result:
                        vulns = result["vulnerabilities"]
                        all_vulnerabilities.extend(vulns)
                        # Count sources
                        semgrep_count += sum(1 for v in vulns if v.get("source") == "semgrep")
                        ai_count += sum(1 for v in vulns if v.get("source") == "ai")
                
                pbar.update(len(batch))
                await asyncio.sleep(self.batch_delay)

        elapsed_time = time.time() - start_time
        
        # Calculate overall security score
        score = 100
        if self.ai_provider and all_vulnerabilities:
            score = self.ai_provider._calculate_security_score(all_vulnerabilities)
        elif all_vulnerabilities:
            score = 50  # If only semgrep results, give a medium score
        
        return {
            "vulnerabilities": all_vulnerabilities,
            "overall_score": score,
            "summary": (f"Found {len(all_vulnerabilities)} vulnerabilities "
                       f"({semgrep_count} from semgrep, {ai_count} from AI analysis). "
                       f"Security Score: {score}%. "
                       f"Scan completed in {elapsed_time:.2f} seconds."),
            "metadata": {
                "scan_time": elapsed_time,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "mode": self.mode.value,
                "files_scanned": len(files_to_scan),
                "skipped_files": skipped_files,
                "files_with_issues": len(set(v.get("file", "") for v in all_vulnerabilities))
            }
        }

    async def run_in_process(self, executor, func, *args):
        """Run a function in a separate process"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(executor, func, *args)

    def _get_changed_files(self, files: List[str]) -> List[str]:
        """Get files changed since last scan"""
        if not self.incremental:
            return files
        
        try:
            last_scan = {}
            if self.last_scan_file.exists():
                with open(self.last_scan_file) as f:
                    last_scan = json.load(f)
            
            if self.verbose:
                print(f"Last scan data: {last_scan}")
                print(f"Files to check: {files}")
            
            changed_files = []
            for file_path in files:
                # 使用相对路径作为键
                rel_path = str(Path(file_path).relative_to(Path.cwd()))
                file_hash = hashlib.md5(Path(file_path).read_bytes()).hexdigest()
                
                if self.verbose:
                    print(f"Checking file: {rel_path}")
                    print(f"  Current hash: {file_hash}")
                    print(f"  Previous hash: {last_scan.get(rel_path)}")
                
                if last_scan.get(rel_path) != file_hash:
                    changed_files.append(file_path)
                    last_scan[rel_path] = file_hash
            
            # 保存新的扫描记录
            self.last_scan_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.last_scan_file, 'w') as f:
                json.dump(last_scan, f)
            
            return changed_files or files
        except Exception as e:
            print(f"Warning: Failed to check changed files: {e}")
            return files

async def _async_main():
    parser = argparse.ArgumentParser(description="Security scanner with multiple scanning modes")
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan code for security issues')
    scan_parser.add_argument("--path", type=str, required=True, help="Path to scan (file or directory)")
    scan_parser.add_argument("--mode", type=str, choices=[mode.value for mode in ScanMode], 
                           default=ScanMode.SEMGREP_ONLY.value,
                           help="Scanning mode: semgrep (basic scan), openai (AI-enhanced scan), or gemini")
    scan_parser.add_argument("--api-key", type=str, help="API key for AI service (required for openai and gemini modes)")
    scan_parser.add_argument("--workers", type=int, default=os.cpu_count(),
                           help="Number of parallel workers (default: number of CPU cores)")
    scan_parser.add_argument("--cache", type=str, default=None,
                           help="Path to cache file (default: no cache between runs)")
    scan_parser.add_argument("--verbose", "-v", action="store_true",
                           help="Show detailed progress information")
    scan_parser.add_argument("--output-dir", type=str, 
                           default=os.path.expanduser("~/.dragonsec/scan_results"),
                           help="Directory to save scan results (default: ~/.dragonsec/scan_results)")
    scan_parser.add_argument("--include-tests", action="store_true",
                           help="Include test files in security scan (default: False)")
    scan_parser.add_argument("--batch-size", type=int, default=4,
                           help="Number of files to process in each batch (default: 4)")
    scan_parser.add_argument("--batch-delay", type=float, default=0.1,
                           help="Delay between batches in seconds (default: 0.1)")

    # List rules command
    list_rules_parser = subparsers.add_parser('rules', help='List available security rules')
    list_rules_parser.add_argument('--list', action='store_true', help='List all available rule sets')

    args = parser.parse_args()

    if args.command == 'rules':
        rule_manager = RuleManager()
        print("\n🔍 Available Security Rule Sets:")
        for rule_id, description in rule_manager.rule_sets.items():
            print(f"  • {description} ({rule_id})")
        print("\nNote: Rules are automatically downloaded and cached when needed")
        return

    if args.command == 'scan':
        # validate parameters
        mode = ScanMode(args.mode)
        if mode != ScanMode.SEMGREP_ONLY and not args.api_key:
            parser.error(f"--api-key is required for {mode.value} mode")

        # load cache
        cache = {}
        if args.cache and os.path.exists(args.cache):
            try:
                with open(args.cache, 'r') as f:
                    cache = json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load cache file: {e}")

        scanner = SecurityScanner(
            mode=mode,
            api_key=args.api_key,
            workers=args.workers,
            cache=cache,
            verbose=args.verbose,
            include_tests=args.include_tests,
            batch_size=args.batch_size,
            batch_delay=args.batch_delay
        )
        
        try:
            # Run scan
            results = await scanner.scan_directory(args.path)
            
            # Create output directory
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate report filename
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            target_name = Path(args.path).name
            report_file = output_dir / f"{timestamp}_{target_name}_{mode.value}_scan.json"
            
            # Save report
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            # Save cache
            if args.cache:
                with open(args.cache, 'w') as f:
                    json.dump(scanner.semgrep_runner.cache, f)
            
            # Print results
            print("\n" + "="*80)
            print(results["summary"])
            print(f"📝 Detailed report saved to: {report_file}")
            print("="*80 + "\n")
            
            if args.verbose:
                print("\n🔍 Detailed scan results:")
                print(json.dumps(results, indent=2, ensure_ascii=False))
            
        except Exception as e:
            print(f"❌ Error during scan: {e}")
            sys.exit(1)

def main():
    """Entry point for the console script"""
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main() 