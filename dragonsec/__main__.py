from dragonsec.core.scanner import main
import argparse
import os
import logging

def main():
    parser = argparse.ArgumentParser()
    # ... 其他参数 ...
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    # 配置日志级别
    log_level = os.getenv('DRAGONSEC_LOG_LEVEL', 'WARNING')
    if args.verbose:
        log_level = 'DEBUG'
    
    # 配置根日志器
    logging.basicConfig(
        level=log_level,
        format='%(message)s'  # 简化非 verbose 模式的输出格式
    )
    
    # 在非 verbose 模式下抑制特定模块的日志
    if not args.verbose:
        logging.getLogger('httpx').setLevel(logging.WARNING)
        logging.getLogger('openai').setLevel(logging.WARNING)

if __name__ == '__main__':
    main() 