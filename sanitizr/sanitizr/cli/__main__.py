#!/usr/bin/env python3
"""
Command-line interface for Sanitizr URL Cleaner.

This module provides a CLI for cleaning URLs using the Sanitizr core engine.
"""

import argparse
import sys
from typing import List, Optional, TextIO

from ..core.cleaner import URLCleaner
from ..config.config import ConfigManager


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="sanitizr",
        description="Clean URLs by removing tracking parameters and decoding redirects.",
    )
    
    parser.add_argument(
        "--input", "-i",
        type=str,
        help="Input file path (one URL per line). If not specified, stdin is used."
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path. If not specified, stdout is used."
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to configuration file (JSON or YAML)."
    )
    
    parser.add_argument(
        "--dry-run", "-d",
        action="store_true",
        help="Show what would be done without actually cleaning."
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show verbose output with before/after comparison (not version, use -V for version)."
    )
    
    parser.add_argument(
        "--url", "-u",
        type=str,
        help="Clean a single URL directly from the command line."
    )
    
    # Import at function level to avoid circular imports
    from .. import __version__
    
    # Version flags - both --version and -V will show version
    version_group = parser.add_argument_group('version')
    version_group.add_argument(
        "--version",
        action="version",
        version=f"sanitizr {__version__}",
        help="Show program's version number and exit."
    )
    version_group.add_argument(
        "-V",
        action="version",
        version=f"sanitizr {__version__}",
        help="Show program's version number and exit (shorthand)."
    )
    
    return parser.parse_args()


def process_urls(
    cleaner: URLCleaner,
    input_stream: TextIO,
    output_stream: TextIO,
    dry_run: bool = False,
    verbose: bool = False,
    interactive: bool = False,
) -> None:
    """
    Process URLs from input stream and write cleaned URLs to output stream.
    
    Args:
        cleaner: URLCleaner instance
        input_stream: Input stream to read URLs from
        output_stream: Output stream to write cleaned URLs to
        dry_run: If True, don't actually clean URLs, just show what would be done
        verbose: If True, show both original and cleaned URLs
        interactive: If True, assume interactive mode with prompts
    """
    # Check if we're dealing with an interactive terminal
    is_interactive_term = interactive and hasattr(input_stream, 'isatty') and input_stream.isatty()
    
    # Show prompt for interactive mode
    if is_interactive_term:
        output_stream.write("Enter URLs to clean (one per line). Press Ctrl+C to exit.\n")
        output_stream.write("Type 'help' for instructions or 'exit' to quit.\n\n")
    
    prompt = "URL> " if is_interactive_term else ""
    
    if prompt:
        output_stream.write(prompt)
        output_stream.flush()
        
    for line in input_stream:
        line = line.strip()
        
        # Handle special commands in interactive mode
        if interactive and line:
            if line.lower() == 'exit' or line.lower() == 'quit':
                break
            elif line.lower() == 'help':
                output_stream.write("\nSanitizr URL Cleaner Help:\n")
                output_stream.write("  Enter a URL to clean tracking parameters and decode redirects\n")
                output_stream.write("  Commands:\n")
                output_stream.write("    help - Show this help message\n")
                output_stream.write("    exit/quit - Exit the program\n\n")
                output_stream.write(prompt)
                output_stream.flush()
                continue
        
        if not line:
            if is_interactive_term:
                output_stream.write(prompt)
                output_stream.flush()
            continue
            
        # Skip comments
        if line.startswith("#"):
            if not dry_run:
                output_stream.write(f"{line}\n")
            if is_interactive_term:
                output_stream.write(prompt)
                output_stream.flush()
            continue
            
        # Clean the URL
        cleaned_url = line if dry_run else cleaner.clean_url(line)
        
        # Output according to options
        if verbose:
            if cleaned_url != line:
                output_stream.write(f"Original: {line}\n")
                output_stream.write(f"Cleaned:  {cleaned_url}\n\n")
            else:
                output_stream.write(f"Unchanged: {line}\n\n")
        else:
            output_stream.write(f"{cleaned_url}\n")
            
        if is_interactive_term:
            output_stream.write(prompt)
            output_stream.flush()


def display_banner() -> None:
    """Display a banner with program info."""
    from .. import __version__
    print(f"""
╔═══════════════════════════════════╗
║ Sanitizr URL Cleaner v{__version__:<11} ║
║ Clean URLs by removing trackers   ║
╚═══════════════════════════════════╝
""")

def main() -> int:
    """Main entry point for the CLI."""
    args = parse_args()
    
    # Load configuration
    try:
        config_manager = ConfigManager(args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        return 1
        
    # Create the URL cleaner
    cleaner = URLCleaner(
        custom_tracking_params=config_manager.get_tracking_params(),
        custom_redirect_params=config_manager.get_redirect_params(),
        whitelist_params=config_manager.get_whitelist_params(),
        blacklist_params=config_manager.get_blacklist_params(),
    )
    
    # Handle single URL case
    if args.url:
        cleaned_url = args.url if args.dry_run else cleaner.clean_url(args.url)
        if args.verbose:
            print(f"Original: {args.url}")
            print(f"Cleaned:  {cleaned_url}")
        else:
            print(cleaned_url)
        return 0
    
    # Determine if we're in interactive mode (no args, stdin is a terminal)
    interactive_mode = not args.input and hasattr(sys.stdin, 'isatty') and sys.stdin.isatty()
    
    # Show banner in interactive mode
    if interactive_mode:
        display_banner()
    
    # Set up input stream
    try:
        if args.input:
            input_stream = open(args.input, "r", encoding="utf-8")
        else:
            input_stream = sys.stdin
    except Exception as e:
        print(f"Error opening input file: {e}", file=sys.stderr)
        return 1
        
    # Set up output stream
    try:
        if args.output:
            output_stream = open(args.output, "w", encoding="utf-8")
        else:
            output_stream = sys.stdout
    except Exception as e:
        print(f"Error opening output file: {e}", file=sys.stderr)
        if args.input and input_stream != sys.stdin:
            input_stream.close()
        return 1
        
    # Process the URLs
    try:
        process_urls(
            cleaner,
            input_stream,
            output_stream,
            dry_run=args.dry_run,
            verbose=args.verbose,
            interactive=interactive_mode
        )
    except KeyboardInterrupt:
        print("\nThank you for using Sanitizr URL Cleaner!", file=sys.stderr)
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        print(f"Error processing URLs: {e}", file=sys.stderr)
        return 1
    finally:
        # Clean up resources
        if args.input and input_stream != sys.stdin:
            input_stream.close()
        if args.output and output_stream != sys.stdout:
            output_stream.close()
            
    return 0


if __name__ == "__main__":
    sys.exit(main())
