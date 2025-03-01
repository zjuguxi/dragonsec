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
from datetime import datetime

from ..providers.base import AIProvider
from ..providers.openai import OpenAIProvider
from ..providers.gemini import GeminiProvider
from dragonsec.utils.semgrep import SemgrepRunner
from ..utils.file_utils import FileContext
from ..utils.rule_manager import RuleManager
from ..providers.deepseek import DeepseekProvider
from ..config import DEFAULT_CONFIG
from ..providers.grok import GrokProvider

# 配置 logger
logger = logging.getLogger(__name__)

class ScanMode(Enum):
    SEMGREP_ONLY = "semgrep"
    OPENAI = "openai"
    GEMINI = "gemini"
    DEEPSEEK = "deepseek"
    GROK = "grok"  # 添加 Grok 模式

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
    def __init__(self, mode: ScanMode = ScanMode.SEMGREP_ONLY, 
                 api_key: str = None, verbose: bool = False,
                 include_tests: bool = False, batch_size: int = None, 
                 batch_delay: float = None):
        # 先从配置获取默认值
        self.batch_size = batch_size or DEFAULT_CONFIG['batch_size']
        self.batch_delay = batch_delay or DEFAULT_CONFIG['batch_delay']
        
        # 然后初始化其他属性
        self.mode = mode
        self.ai_provider = self._create_provider(mode, api_key) if mode != ScanMode.SEMGREP_ONLY else None
        self.semgrep_runner = SemgrepRunner()
        self.file_context = FileContext()
        self.verbose = verbose
        
        # 使用配置文件中的值
        self.skip_dirs = DEFAULT_CONFIG['skip_dirs']
        self.test_dir_patterns = DEFAULT_CONFIG['test_dir_patterns']
        self.test_file_patterns = DEFAULT_CONFIG['test_file_patterns']
        
        # 支持的文件类型
        self.supported_extensions = {
            'py', '.py',      # Python
            'js', '.js',      # JavaScript
            'java', '.java',  # Java
            'go', '.go',      # Go
            'php', '.php',    # PHP
            'ts', '.ts',      # TypeScript
            'jsx', '.jsx',    # React
            'tsx', '.tsx',    # React + TypeScript
            'vue', '.vue',    # Vue
            'rb', '.rb',      # Ruby
            'rs', '.rs',      # Rust
            'c', '.c',        # C
            'cpp', '.cpp',    # C++
            'cs', '.cs',      # C#
            'swift', '.swift' # Swift
        }
        
        # 设置日志级别
        root_logger = logging.getLogger()
        if verbose:
            root_logger.setLevel(logging.DEBUG)
        else:
            # 在非 verbose 模式下，设置更高的日志级别
            root_logger.setLevel(logging.WARNING)
            # 特别设置 httpx 和 openai 的日志级别
            logging.getLogger('httpx').setLevel(logging.WARNING)
            logging.getLogger('openai').setLevel(logging.WARNING)

    def _create_provider(self, mode: ScanMode, api_key: str) -> AIProvider:
        providers = {
            ScanMode.OPENAI: OpenAIProvider,
            ScanMode.GEMINI: GeminiProvider,
            ScanMode.DEEPSEEK: DeepseekProvider,
            ScanMode.GROK: GrokProvider  # 添加 Grok provider
        }
        return providers[mode](api_key)

    def _should_scan_file(self, file_path: str) -> bool:
        """检查是否应该扫描该文件"""
        try:
            # 获取文件扩展名（带点和不带点的形式）
            ext_with_dot = os.path.splitext(file_path)[1].lower()
            ext_no_dot = ext_with_dot[1:] if ext_with_dot.startswith('.') else ext_with_dot
            
            # 检查是否为 Dockerfile
            is_dockerfile = os.path.basename(file_path).lower() == 'dockerfile'
            
            logger.debug(f"Checking file: {file_path}")
            logger.debug(f"File extension (with dot): {ext_with_dot}")
            logger.debug(f"File extension (no dot): {ext_no_dot}")
            logger.debug(f"Is Dockerfile: {is_dockerfile}")
            logger.debug(f"Supported extensions: {self.supported_extensions}")
            
            # 如果是支持的文件类型或是 Dockerfile
            if ext_with_dot in self.supported_extensions or \
               ext_no_dot in self.supported_extensions or \
               is_dockerfile:
                
                # 检查文件大小
                if os.path.getsize(file_path) > 1024 * 1024:  # 1MB
                    logger.debug(f"Skipping large file: {file_path}")
                    return False
                
                # 检查是否为空文件
                if os.path.getsize(file_path) == 0:
                    logger.debug(f"Skipping empty file: {file_path}")
                    return False
                
                # 检查是否为二进制文件
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        f.read(1024)  # 只读取前1KB来检查
                    return True
                except UnicodeDecodeError:
                    logger.debug(f"Skipping binary file: {file_path}")
                    return False
                
            return False
            
        except Exception as e:
            logger.error(f"Error checking file {file_path}: {e}")
            return False

    async def scan_file(self, file_path: str) -> Dict:
        """Scan a single file"""
        try:
            if self.verbose:
                logger.debug(f"Starting scan of file: {file_path}")  # 改为 DEBUG 级别
            
            results = []
            
            # 只在 SEMGREP_ONLY 模式下运行 semgrep
            if self.mode == ScanMode.SEMGREP_ONLY:
                semgrep_results = await self.semgrep_runner.run_scan(file_path)
                results.extend(self.semgrep_runner.format_results(semgrep_results))
            
            # 运行 AI 分析
            if self.mode != ScanMode.SEMGREP_ONLY:
                if self.verbose:
                    logger.debug("Running AI analysis")  # 改为 DEBUG 级别
                context = self.file_context.get_context(file_path)
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                ai_results = await self.ai_provider.analyze_code(
                    code=code,
                    file_path=file_path,
                    context=context
                )
                
                if "vulnerabilities" in ai_results:
                    if self.verbose:
                        logger.debug(f"AI analysis completed with {len(ai_results['vulnerabilities'])} findings")
                    results.extend(ai_results["vulnerabilities"])
                else:
                    if self.verbose:
                        logger.debug("AI analysis completed with no findings")
            
            return {"vulnerabilities": results}
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")  # 错误信息保持 ERROR 级别
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

    async def scan_directory(self, directory: str, mode: str = "openai") -> Dict:
        """扫描指定目录下的所有文件"""
        try:
            directory = os.path.abspath(os.path.expanduser(directory))
            self.file_context.set_scan_root(directory)
            
            if self.verbose:
                logger.debug(f"Scanning directory: {directory}")  # 改为 DEBUG 级别
            
            if not os.path.exists(directory):
                return {
                    "vulnerabilities": [],
                    "overall_score": 100,
                    "summary": "Directory not found",
                    "metadata": {
                        "files_scanned": 0,
                        "skipped_files": 0,
                        "scan_duration": 0,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "mode": mode,
                        "error": f"Directory not found: {directory}"
                    }
                }
            
            # 获取所有支持的文件
            files_to_scan = []
            skipped_files = 0
            
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_scan_file(file_path):
                        files_to_scan.append(file_path)
                    else:
                        skipped_files += 1
            
            logger.info(f"Found {len(files_to_scan)} files to scan, skipped {skipped_files} files")
            
            if not files_to_scan:
                # 如果没有文件要扫描，返回空结果而不是 None
                return {
                    "vulnerabilities": [],
                    "overall_score": 100,
                    "summary": "No files to scan",
                    "metadata": {
                        "scan_duration": 0,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "mode": mode,
                        "files_scanned": 0,
                        "skipped_files": skipped_files,
                        "files_with_issues": 0,
                        "semgrep_findings": 0,
                        "ai_findings": 0
                    }
                }
            
            start_time = time.perf_counter()
            
            # 扫描所有文件
            results = []
            with tqdm(total=len(files_to_scan), desc="Scanning files") as pbar:
                for i in range(0, len(files_to_scan), self.batch_size):
                    batch = files_to_scan[i:i + self.batch_size]
                    batch_results = await asyncio.gather(*[
                        self.scan_file(file) for file in batch
                    ])
                    results.extend(batch_results)
                    pbar.update(len(batch))
                    if i + self.batch_size < len(files_to_scan):
                        await asyncio.sleep(self.batch_delay)
            
            # 如果是 AI 模式，发送所有结果给 AI 去重
            if mode != ScanMode.SEMGREP_ONLY:
                all_vulns = []
                for result in results:
                    all_vulns.extend(result.get("vulnerabilities", []))
                
                if all_vulns:
                    try:
                        dedup_vulns = await self.ai_provider.deduplicate_vulnerabilities(all_vulns)
                        results = [{"vulnerabilities": dedup_vulns}]
                    except Exception as e:
                        logger.error(f"Error during vulnerability deduplication: {e}")
            
            # 计算扫描时间
            scan_duration = time.perf_counter() - start_time
            
            # 汇总结果
            summary = self._summarize_results(results)
            summary["metadata"] = {
                "scan_duration": scan_duration,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "mode": mode,
                "files_scanned": len(files_to_scan),
                "skipped_files": skipped_files,
                "files_with_issues": len([r for r in results if r.get("vulnerabilities")]),
                "semgrep_findings": len([v for r in results for v in r.get("vulnerabilities", []) 
                                       if v.get("source") == "semgrep"]),
                "ai_findings": len([v for r in results for v in r.get("vulnerabilities", [])
                                  if v.get("source") == "ai"])
            }
            
            # Create output directory
            output_dir = Path(os.path.expanduser("~/.dragonsec/scan_results"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate report filename
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            target_name = Path(directory).name
            report_file = output_dir / f"{timestamp}_{target_name}_{mode}_scan.json"
            
            # Save report
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            
            # 只在 verbose 模式下打印详细结果
            if self.verbose:
                print("\n🔍 Detailed scan results:")
                print(json.dumps(summary, indent=2, ensure_ascii=False))
            else:
                # 非 verbose 模式只打印简要信息
                print("\n" + "="*80)
                print(summary["summary"])
                print(f"📝 Detailed report saved to: {report_file}")
                print("="*80 + "\n")
            
            return summary
            
        except Exception as e:
            return {
                "vulnerabilities": [],
                "overall_score": 100,
                "summary": f"Error during scan: {str(e)}",
                "metadata": {
                    "files_scanned": 0,
                    "skipped_files": 0,
                    "scan_duration": 0,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "mode": mode,
                    "error": str(e)
                }
            }

    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate security score based on vulnerabilities"""
        if self.ai_provider and vulnerabilities:
            return self.ai_provider._calculate_security_score(vulnerabilities)
        elif vulnerabilities:
            return 50  # If only semgrep results, give a medium score
        else:
            return 100  # No vulnerabilities found

    def _get_error_result(self) -> Dict:
        """Get error result"""
        return {
            "vulnerabilities": [],
            "overall_score": 100,
            "summary": "No files to scan",
            "metadata": {
                "files_scanned": 0,
                "skipped_files": 0,
                "scan_duration": 0,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "mode": self.mode.value,
                "error": "Error during scan"
            }
        }

    def _summarize_results(self, all_results: List[Dict]) -> Dict:
        """Summarize scan results"""
        total_vulns = []
        semgrep_vulns = []
        ai_vulns = []
        
        for result in all_results:
            if "vulnerabilities" in result:
                vulns = result["vulnerabilities"]
                total_vulns.extend(vulns)
                
                # 分别统计 semgrep 和 AI 的结果
                for vuln in vulns:
                    if vuln.get("source") == "semgrep":
                        semgrep_vulns.append(vuln)
                    elif vuln.get("source") == "ai":
                        ai_vulns.append(vuln)
        
        # 计算整体安全分数
        score = self._calculate_security_score(total_vulns)
        
        # 根据扫描模式显示统计信息
        if self.mode == ScanMode.SEMGREP_ONLY:
            summary = f"Found {len(total_vulns)} vulnerabilities from semgrep"
        else:
            summary = (
                f"Found {len(total_vulns)} vulnerabilities "
                f"({len(semgrep_vulns)} from semgrep, {len(ai_vulns)} from AI analysis)"
            )
        
        return {
            "vulnerabilities": total_vulns,
            "overall_score": score,
            "summary": f"{summary}. Security Score: {score}%"
        }

async def _async_main():
    """Main async function"""
    parser = argparse.ArgumentParser(
        description="DragonSec - AI-enhanced security scanner"
    )
    
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan code for security issues')
    scan_parser.add_argument("--path", type=str, required=True, help="Path to scan (file or directory)")
    scan_parser.add_argument("--mode", type=str, choices=[mode.value for mode in ScanMode], 
                           default=ScanMode.SEMGREP_ONLY.value,
                           help="Scanning mode: semgrep (basic scan), openai (GPT-4o), gemini (Gemini-1.5-flash), or deepseek (R1)")
    scan_parser.add_argument("--api-key", type=str, help="API key for AI service (required for AI modes)")
    scan_parser.add_argument("--batch-size", type=int, default=4,
                           help="Number of files to process in each batch (default: 4)")
    scan_parser.add_argument("--batch-delay", type=float, default=0.1,
                           help="Delay between batches in seconds (default: 0.1)")
    scan_parser.add_argument("--verbose", "-v", action="store_true",
                           help="Show detailed progress information")
    scan_parser.add_argument("--output-dir", type=str, 
                           default=os.path.expanduser("~/.dragonsec/scan_results"),
                           help="Directory to save scan results (default: ~/.dragonsec/scan_results)")
    scan_parser.add_argument("--include-tests", action="store_true",
                           help="Include test files in security scan (default: False)")

    # Rules command (simplified)
    subparsers.add_parser('rules', help='List available security rules')

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

        scanner = SecurityScanner(
            mode=mode,
            api_key=args.api_key,
            verbose=args.verbose,
            include_tests=args.include_tests,
            batch_size=args.batch_size,
            batch_delay=args.batch_delay
        )
        
        try:
            # Run scan
            await scanner.scan_directory(args.path, args.mode)
            
        except Exception as e:
            print(f"❌ Error during scan: {e}")
            sys.exit(1)

def main():
    """Entry point for the console script"""
    try:
        import cProfile
        profiler = cProfile.Profile()
        profiler.enable()
        
        asyncio.run(_async_main())
        
        profiler.disable()
        profiler.dump_stats('scan.prof')
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main() 