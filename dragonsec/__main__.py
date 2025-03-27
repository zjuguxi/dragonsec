import argparse
import sys
import asyncio
import os
import logging
from dragonsec.core.scanner import SecurityScanner, ScanMode


def main():
    """Main entry point for the dragonsec command line tool"""
    parser = argparse.ArgumentParser(description="DragonSec Security Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Add scan command
    scan_parser = subparsers.add_parser("scan", help="Scan code for security issues")
    SecurityScanner.add_arguments(scan_parser)

    # Add rules command (placeholder)
    rules_parser = subparsers.add_parser("rules", help="Manage security rules")
    rules_parser.add_argument(
        "--list", action="store_true", help="List available rules"
    )

    # Parse arguments
    args = parser.parse_args()

    # Configure logging
    log_level = os.getenv("DRAGONSEC_LOG_LEVEL", "WARNING")
    if hasattr(args, "verbose") and args.verbose:
        log_level = "DEBUG"

    # Configure root logger
    logging.basicConfig(
        level=log_level, format="%(message)s"  # Simplified format for non-verbose mode
    )

    # Suppress logs from specific modules in non-verbose mode
    if log_level != "DEBUG":
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("openai").setLevel(logging.WARNING)

    # Execute command
    if args.command == "scan":
        try:
            asyncio.run(SecurityScanner._async_main())
        except KeyboardInterrupt:
            print("\nScan interrupted by user")
            sys.exit(1)
    elif args.command == "rules":
        if args.list:
            print("Available security rules:")
            # TODO: Implement rule listing
            print("  (Rule listing not yet implemented)")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
