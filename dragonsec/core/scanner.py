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
        self.verbose = verbose
        self.include_tests = include_tests
        self.batch_size = batch_size
        self.batch_delay = batch_delay
        self.incremental = incremental
        self.last_scan_file = Path.home() / ".dragonsec" / "last_scan.json"
        # 定义测试相关的模式
        self.test_dir_patterns = {'tests', 'test', '__tests__', '__test__', 'testing'}
        self.test_file_patterns = {'test_', '_test', 'tests.', '.test.', 'spec.', '.spec.'}
        self.workers = workers

    def _create_provider(self, mode: ScanMode, api_key: str) -> AIProvider:
        providers = {
            ScanMode.OPENAI: OpenAIProvider,
            ScanMode.GEMINI: GeminiProvider
        }
        return providers[mode](api_key)

    def _is_test_directory(self, path: str) -> bool:
        """Check if a directory is a test directory"""
        path_parts = Path(path).parts
        return any(part.lower() in self.test_dir_patterns for part in path_parts)

    def _is_test_file(self, filename: str) -> bool:
        """Check if a file is a test file"""
        filename = filename.lower()
        return any(pattern in filename for pattern in self.test_file_patterns)

    def _should_skip_path(self, path: str, is_dir: bool = True) -> bool:
        """Determine if a path should be skipped based on test patterns"""
        if self.include_tests:
            return False
            
        if is_dir:
            return self._is_test_directory(path)
        else:
            return self._is_test_directory(str(Path(path).parent)) or self._is_test_file(Path(path).name)

    async def scan_file(self, file_path: str) -> Dict:
        """Scan a single file"""
        # 1. 先运行 semgrep 扫描
        semgrep_results = await self.semgrep_runner.run_scan(file_path)
        
        # 如果没有配置 AI，直接返回 semgrep 结果
        if not self.ai_provider:
            return {"vulnerabilities": self.semgrep_runner.format_results(semgrep_results)}
            
        # 2. 再运行 AI 分析
        try:
            file_context = self.file_context.get_context(file_path)
            ai_results = await self.ai_provider.analyze_code(
                code=file_context["content"],
                file_path=file_path,
                context=file_context
            )
            
            # 3. 合并两种结果
            return self.ai_provider.merge_results(
                self.semgrep_runner.format_results(semgrep_results),
                ai_results
            )
        except UnicodeDecodeError:
            print(f"Warning: Could not read {file_path} as text file, skipping AI analysis")
            return {"vulnerabilities": self.semgrep_runner.format_results(semgrep_results)}

    async def process_batch(self, files: List[str]) -> List[Dict]:
        """并行处理一批文件"""
        tasks = [self.scan_file(f) for f in files]
        return await asyncio.gather(*tasks)

    async def scan_directory(self, path: str) -> Dict:
        """Scan an entire directory or single file"""
        path = os.path.expanduser(path)
        start_time = time.time()
        
        if os.path.isfile(path):
            if self._should_skip_path(path, is_dir=False):
                print(f"Skipping test file: {path}")
                return {
                    "vulnerabilities": [],
                    "summary": "Skipped test file",
                    "overall_score": 100  # 添加这个字段
                }
                
            with tqdm(total=1, desc="Scanning files") as pbar:
                result = await self.scan_file(path)
                pbar.update(1)
                return result
                
        elif os.path.isdir(path):
            print("\n📂 Collecting files to scan...")
            files_to_scan = []
            for root, _, files in os.walk(path):
                if self._should_skip_path(root):
                    if self.verbose:
                        print(f"  Skipping directory: {root}")
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_skip_path(file_path, is_dir=False):
                        if self.verbose:
                            print(f"  Skipping test file: {file_path}")
                        continue
                        
                    if file.endswith(('.py', '.js', '.ts', '.java', '.go', '.php')):
                        files_to_scan.append(file_path)
                        if self.verbose:
                            print(f"  Added: {file_path}")

            total_files = len(files_to_scan)
            print(f"\n🔍 Found {total_files} files to scan")
            
            if total_files == 0:
                return {
                    "vulnerabilities": [],
                    "overall_score": 100,
                    "summary": "No files to scan",
                    "metadata": {
                        "scan_time": 0,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "mode": self.mode.value,
                        "files_scanned": 0,
                        "files_with_issues": 0
                    }
                }

            # 分批处理文件
            all_vulnerabilities = []  # 用一个列表存储所有漏洞
            semgrep_count = 0
            ai_count = 0
            
            with tqdm(total=total_files, desc="Scanning files") as pbar:
                for i in range(0, len(files_to_scan), self.batch_size):
                    batch = files_to_scan[i:i + self.batch_size]
                    batch_results = await self.process_batch(batch)
                    
                    # 合并每个文件的结果
                    for result in batch_results:
                        if "vulnerabilities" in result:
                            vulns = result["vulnerabilities"]
                            all_vulnerabilities.extend(vulns)
                            # 统计来源
                            semgrep_count += sum(1 for v in vulns if v.get("source") == "semgrep")
                            ai_count += sum(1 for v in vulns if v.get("source") == "ai")
                    
                    pbar.update(len(batch))
                    await asyncio.sleep(self.batch_delay)

            elapsed_time = time.time() - start_time
            
            # 计算总体安全分数
            score = 100
            if self.ai_provider and all_vulnerabilities:
                score = self.ai_provider._calculate_security_score(all_vulnerabilities)
            elif all_vulnerabilities:
                score = 50  # 如果只有 semgrep 结果，给出中等分数
            
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
                    "files_scanned": total_files,
                    "files_with_issues": len(set(v.get("file", "") for v in all_vulnerabilities))
                }
            }
        else:
            raise FileNotFoundError(f"Path not found: {path}")

    async def run_in_process(self, executor, func, *args):
        """在单独的进程中运行函数"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(executor, func, *args)

    def _get_changed_files(self, path: str) -> List[str]:
        """获取自上次扫描以来修改的文件"""
        if not self.incremental or not self.last_scan_file.exists():
            return None  # 返回 None 表示需要全量扫描
            
        try:
            with open(self.last_scan_file) as f:
                last_scan = json.load(f)
            
            changed_files = []
            for file_path in self._collect_files(path):
                file_hash = self._get_file_hash(file_path)
                if last_scan.get(file_path) != file_hash:
                    changed_files.append(file_path)
            
            return changed_files
        except Exception:
            return None

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