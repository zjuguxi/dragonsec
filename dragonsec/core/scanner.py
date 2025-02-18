import subprocess
import json
import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import asyncio
from tqdm import tqdm
import time
from enum import Enum
import hashlib
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
import logging
import cProfile
import pstats
from functools import wraps

from ..providers.base import AIProvider
from ..providers.openai import OpenAIProvider
from ..providers.gemini import GeminiProvider
from dragonsec.utils.semgrep import SemgrepRunner
from ..utils.file_utils import FileContext
from ..utils.rule_manager import RuleManager
from ..providers.deepseek import DeepseekProvider

# 配置 logger
logger = logging.getLogger(__name__)

class ScanMode(Enum):
    SEMGREP_ONLY = "semgrep"
    OPENAI = "openai"
    GEMINI = "gemini"
    DEEPSEEK = "deepseek"  # 添加新的模式

def profile_async(func):
    """Profile async function"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        try:
            return await profiler.runcall(func, *args, **kwargs)
        finally:
            stats = pstats.Stats(profiler)
            stats.sort_stats('cumulative')
            stats.print_stats(50)  # 显示前50个耗时最多的函数
    return wrapper

def time_async(func):
    """Time async function execution"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            return await func(*args, **kwargs)
        finally:
            elapsed = time.perf_counter() - start
            logger.info(f"{func.__name__} took {elapsed:.2f} seconds")
    return wrapper

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
            ScanMode.GEMINI: GeminiProvider,
            ScanMode.DEEPSEEK: DeepseekProvider  # 添加新的 provider
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

    @time_async
    async def scan_file(self, file_path: str) -> Dict:
        """Scan a single file"""
        try:
            logger.info(f"Starting scan of file: {file_path}")
            
            # 获取相对路径
            rel_path = str(Path(file_path).relative_to(Path.cwd()))
            
            # 获取文件上下文
            context = self.file_context.get_context(file_path)
            
            # 初始化结果
            semgrep_results = []
            ai_results = {"vulnerabilities": []}
            
            # 只在 SEMGREP_ONLY 模式或者 incremental 模式下运行 semgrep
            if self.mode == ScanMode.SEMGREP_ONLY:
                logger.info("Running semgrep scan")
                semgrep_results = await self.semgrep_runner.run_scan(file_path)
                semgrep_results = self.semgrep_runner.format_results(semgrep_results)
            
            # 只在 AI 模式下运行 AI 分析
            if self.mode != ScanMode.SEMGREP_ONLY and self.ai_provider:
                logger.info("Running AI analysis")
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                ai_results = await self.ai_provider.analyze_code(
                    code=code,
                    file_path=file_path,
                    context=context
                )
                logger.info(f"AI analysis completed with {len(ai_results.get('vulnerabilities', []))} findings")
            
            # 合并结果
            result = {"vulnerabilities": semgrep_results} if self.mode == ScanMode.SEMGREP_ONLY else ai_results
            for vuln in result.get("vulnerabilities", []):
                if "file" not in vuln or not vuln["file"]:
                    vuln["file"] = rel_path
            
            logger.info(f"Scan completed for {file_path}")
            return result
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return {"vulnerabilities": []}

    async def process_batch(self, files: List[str]) -> List[Dict]:
        """Process a batch of files"""
        if not self.ai_provider:
            return await asyncio.gather(*[self.scan_file(f) for f in files])

        # 准备批处理数据
        file_contents = []
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                    file_contents.append((code, file_path))
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {e}")
                continue

        # 使用 AI provider 的批处理功能
        if hasattr(self.ai_provider, 'analyze_batch'):
            results = await self.ai_provider.analyze_batch(file_contents)
        else:
            results = await asyncio.gather(*[
                self.scan_file(f) for f in files
            ], return_exceptions=True)

        return [r for r in results if not isinstance(r, Exception)]

    @profile_async
    async def scan_directory(self, directory: str) -> Dict:
        """Scan a directory for security issues"""
        try:
            start_time = time.perf_counter()
            logger.info(f"Scanning directory: {directory}")
            
            # 收集要扫描的文件，并获取跳过的文件数
            files_to_scan, skipped_count = self._collect_files(directory)
            total_files = len(files_to_scan)
            
            if not files_to_scan:
                logger.info("No files to scan")
                return {
                    "vulnerabilities": [],
                    "overall_score": 100,
                    "summary": "No files to scan",
                    "metadata": {
                        "files_scanned": 0,
                        "skipped_files": skipped_count,  # 使用实际跳过的文件数
                        "scan_duration": 0,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "mode": self.mode.value
                    }
                }
            
            logger.info(f"\n🔍 Found {total_files} files to scan")
            
            # 创建进度条
            progress = tqdm(
                total=total_files,
                desc="Scanning files",
                unit="file"
            )
            
            all_results = []
            try:
                # 按批次处理文件
                for i in range(0, len(files_to_scan), self.batch_size):
                    batch = files_to_scan[i:i + self.batch_size]
                    batch_results = await self.process_batch(batch)
                    
                    # 更新进度和统计
                    progress.update(len(batch))
                    all_results.extend(batch_results)
                    
                    # 批次间延迟
                    if i + self.batch_size < len(files_to_scan):
                        await asyncio.sleep(self.batch_delay)
            finally:
                progress.close()
            
            # 计算扫描时间
            scan_duration = time.perf_counter() - start_time
            
            # 合并结果
            vulnerabilities = []
            for result in all_results:
                if result and "vulnerabilities" in result:
                    vulnerabilities.extend(result["vulnerabilities"])
            
            # 计算安全分数
            score = self._calculate_security_score(vulnerabilities)
            
            # 统计有问题的文件数
            files_with_issues = len(set(
                vuln["file"] for vuln in vulnerabilities 
                if "file" in vuln
            ))
            
            # 统计 AI 和 semgrep 发现的漏洞数量
            ai_findings = len([v for v in vulnerabilities if v.get("source") == "ai"])
            semgrep_findings = len([v for v in vulnerabilities if v.get("source") == "semgrep"])
            
            return {
                "vulnerabilities": vulnerabilities,
                "overall_score": score,
                "summary": (f"Found {len(vulnerabilities)} vulnerabilities "
                           f"({semgrep_findings} from semgrep, {ai_findings} from AI analysis). "
                           f"Security Score: {score}%. "
                           f"Scan completed in {scan_duration:.2f} seconds."),
                "metadata": {
                    "scan_duration": scan_duration,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "mode": self.mode.value,
                    "files_scanned": total_files,
                    "skipped_files": skipped_count,  # 使用实际跳过的文件数
                    "files_with_issues": files_with_issues,
                    "semgrep_findings": semgrep_findings,
                    "ai_findings": ai_findings
                }
            }
            
        except Exception as e:
            logger.error(f"Error scanning directory: {e}")
            return self._get_error_result()

    async def _scan_file_with_progress(self, file_path: str, semaphore: asyncio.Semaphore, 
                                     progress: tqdm) -> Dict:
        """Scan a single file and update progress"""
        try:
            async with semaphore:
                result = await self.scan_file(file_path)
                progress.update(1)  # 更新进度
                progress.refresh()  # 强制刷新显示
                return result
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            progress.update(1)  # 即使出错也更新进度
            progress.refresh()
            return {"vulnerabilities": []}

    def _collect_files(self, directory: str) -> Tuple[List[str], int]:
        """Collect files to scan and return tuple of (files_to_scan, skipped_count)"""
        files_to_scan = []
        skipped_count = 0
        
        try:
            for root, dirs, files in os.walk(directory):
                # 跳过要忽略的目录
                dirs[:] = [d for d in dirs if d not in self.skip_dirs]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # 检查文件是否应该跳过
                    if self._should_skip_file(file_path):
                        skipped_count += 1
                        logger.debug(f"Skipping file: {file_path}")
                        continue
                    
                    files_to_scan.append(file_path)
                    
            logger.debug(f"Found {len(files_to_scan)} files to scan, skipped {skipped_count} files")
            return files_to_scan, skipped_count
            
        except Exception as e:
            logger.error(f"Error collecting files: {e}")
            return [], 0

    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate security score based on vulnerabilities"""
        if self.ai_provider and vulnerabilities:
            return self.ai_provider._calculate_security_score(vulnerabilities)
        elif vulnerabilities:
            return 50  # If only semgrep results, give a medium score
        else:
            return 100  # No vulnerabilities found

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

    def _get_error_result(self) -> Dict:
        """Get error result"""
        return {
            "vulnerabilities": [],
            "overall_score": 100,
            "summary": "Error scanning directory",
            "metadata": {
                "files_scanned": 0,
                "skipped_files": 0,
                "scan_duration": 0
            }
        }

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