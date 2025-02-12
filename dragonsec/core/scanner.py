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

from ..providers.base import AIProvider
from ..providers.openai import OpenAIProvider
from ..providers.gemini import GeminiProvider
from ..utils.semgrep import SemgrepRunner
from ..utils.file_utils import FileContext

class ScanMode(Enum):
    SEMGREP_ONLY = "semgrep"
    OPENAI = "openai"
    GEMINI = "gemini"

class SecurityScanner:
    def __init__(self, mode: ScanMode = ScanMode.SEMGREP_ONLY, api_key: str = None, 
                 workers: int = os.cpu_count(), cache: Dict = None, verbose: bool = False,
                 include_tests: bool = False, batch_size: int = 10, batch_delay: float = 2.0):
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
        # 定义测试相关的模式
        self.test_dir_patterns = {'tests', 'test', '__tests__', '__test__', 'testing'}
        self.test_file_patterns = {'test_', '_test', 'tests.', '.test.', 'spec.', '.spec.'}

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
        # Run semgrep scan
        semgrep_results = await self.semgrep_runner.run_scan(file_path)
        
        if not self.ai_provider:
            return {"vulnerabilities": self.semgrep_runner.format_results(semgrep_results)}
            
        # Run AI analysis
        try:
            file_context = self.file_context.get_context(file_path)
            ai_results = await self.ai_provider.analyze_code(
                code=file_context["content"],
                file_path=file_path,
                context=file_context
            )
            
            return self.ai_provider.merge_results(
                self.semgrep_runner.format_results(semgrep_results),
                ai_results
            )
        except UnicodeDecodeError:
            print(f"Warning: Could not read {file_path} as text file, skipping AI analysis")
            return {"vulnerabilities": self.semgrep_runner.format_results(semgrep_results)}

    async def scan_directory(self, path: str) -> Dict:
        """Scan an entire directory or single file"""
        path = os.path.expanduser(path)
        start_time = time.time()
        
        if os.path.isfile(path):
            if self._should_skip_path(path, is_dir=False):
                print(f"Skipping test file: {path}")
                return {"vulnerabilities": [], "summary": "Skipped test file"}
                
            with tqdm(total=1, desc="Scanning files") as pbar:
                result = await self.scan_file(path)
                pbar.update(1)
                return result
                
        elif os.path.isdir(path):
            files_to_scan = []
            for root, _, files in os.walk(path):
                if self._should_skip_path(root):
                    if self.verbose:
                        print(f"Skipping test directory: {root}")
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_skip_path(file_path, is_dir=False):
                        if self.verbose:
                            print(f"Skipping test file: {file_path}")
                        continue
                        
                    if file.endswith(('.py', '.js', '.ts', '.java', '.go', '.php')):
                        files_to_scan.append(file_path)

            total_files = len(files_to_scan)
            all_results = []
            semgrep_count = 0
            ai_count = 0
            
            # Process files in smaller batches
            with tqdm(total=total_files, desc=f"Scanning with {self.mode.value}") as pbar:
                for i in range(0, len(files_to_scan), self.batch_size):
                    batch = files_to_scan[i:i + self.batch_size]
                    tasks = [self.scan_file(file) for file in batch]
                    
                    try:
                        batch_results = await asyncio.gather(*tasks)
                        for result in batch_results:
                            if result and "vulnerabilities" in result:
                                vulns = result["vulnerabilities"]
                                all_results.extend(vulns)
                                semgrep_count += sum(1 for v in vulns if v.get("source") == "semgrep")
                                ai_count += sum(1 for v in vulns if v.get("source") == "ai")
                        pbar.update(len(batch))
                        
                        # 成功处理后等待
                        if i > 0:
                            await asyncio.sleep(self.batch_delay)
                            
                    except Exception as e:
                        print(f"Error in batch: {e}")
                        # 出错后增加延迟
                        await asyncio.sleep(self.batch_delay * 2)
                        continue

            elapsed_time = time.time() - start_time
            
            # calculate overall security score
            score = 100
            if self.ai_provider:
                score = self.ai_provider._calculate_security_score(all_results)
            elif all_results:
                score = 50  # if only semgrep results, give a medium score
            
            return {
                "vulnerabilities": all_results,
                "overall_score": score,
                "summary": (f"Found {len(all_results)} vulnerabilities "
                          f"({semgrep_count} from semgrep, {ai_count} from AI analysis). "
                          f"Security Score: {score}%. "
                          f"Scan completed in {elapsed_time:.2f} seconds."),
                "metadata": {
                    "scan_time": elapsed_time,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "mode": self.mode.value,
                    "files_scanned": total_files,
                    "files_with_issues": len(set(v.get("file", "") for v in all_results))
                }
            }
        else:
            raise FileNotFoundError(f"Path not found: {path}")

async def _async_main():
    parser = argparse.ArgumentParser(description="Security scanner with multiple scanning modes")
    parser.add_argument("--path", type=str, required=True, help="Path to scan (file or directory)")
    parser.add_argument("--mode", type=str, choices=[mode.value for mode in ScanMode], 
                       default=ScanMode.SEMGREP_ONLY.value,
                       help="Scanning mode: semgrep (basic scan), openai (AI-enhanced scan), or gemini")
    parser.add_argument("--api-key", type=str, help="API key for AI service (required for openai and gemini modes)")
    parser.add_argument("--workers", type=int, default=os.cpu_count(),
                       help="Number of parallel workers (default: number of CPU cores)")
    parser.add_argument("--cache", type=str, default=None,
                       help="Path to cache file (default: no cache between runs)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Show detailed progress information")
    parser.add_argument("--output-dir", type=str, default="dragonsec/scan_results",
                       help="Directory to save scan results (default: dragonsec/scan_results)")
    parser.add_argument("--include-tests", action="store_true",
                       help="Include test files in security scan (default: False)")
    parser.add_argument("--batch-size", type=int, default=4,
                       help="Number of files to process in each batch (default: 4)")
    parser.add_argument("--batch-delay", type=float, default=0.1,
                       help="Delay between batches in seconds (default: 0.1)")
    args = parser.parse_args()

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