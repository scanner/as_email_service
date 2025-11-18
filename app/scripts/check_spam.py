#!/usr/bin/env python3
"""
Check email messages for spam using SpamAssassin and print the report.

Usage:
    python check_spam.py message1.txt message2.txt message3.txt
"""
import asyncio
import sys
from pathlib import Path

import aiospamc
from rich.pretty import pprint


async def check_spam_file(file_path: Path):
    """Check a single email file with SpamAssassin."""
    try:
        # Read the message file
        msg_bytes = file_path.read_bytes()

        # Use 'report' instead of 'check' to get the detailed spam report
        result = await aiospamc.report(msg_bytes, host="spamassassin", port=783)

        # Print file header
        print(f"\n{'=' * 70}")
        print(f"File: {file_path}")
        print(f"{'=' * 70}")

        # Print spam status
        print("Headers:")
        res_dict = result.to_json()
        pprint(res_dict["headers"])
        print()

        # Print the detailed spam report from the body
        print("SpamAssassin Report:")
        print("=" * 70)
        if result.body:
            print(result.body.decode("utf-8", errors="replace"))
        else:
            print("No report available")
        print()

        # Debug info
        print("Additional Info:")
        print("-" * 70)
        pprint(f"Status: {result.status_code} ({result.message})")
        pprint(f"All headers: {result.headers}")

    except FileNotFoundError:
        print(f"Error: File not found: {file_path}", file=sys.stderr)
    except Exception as e:
        print(f"Error checking {file_path}: {e!r}", file=sys.stderr)


async def main():
    """Check all provided email files."""
    if len(sys.argv) < 2:
        print(
            "Usage: python check_spam.py message1.txt [message2.txt ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    # Process each file
    for file_path_str in sys.argv[1:]:
        file_path = Path(file_path_str)
        await check_spam_file(file_path)


if __name__ == "__main__":
    asyncio.run(main())
