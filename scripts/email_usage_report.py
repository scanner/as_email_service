#!/usr/bin/env python
#
"""
Report mailbox usage for all email accounts with local delivery.

Enumerates all LocalDelivery instances, counts messages per folder
(Inbox, Deleted Messages, Junk, Archive), and calculates total disk
usage per account. Also detects orphaned mail directories on disk that
no longer have a corresponding LocalDelivery in the database.

Run from inside a running container:

    cd /app && python ../scripts/email_usage_report.py
"""

# system imports
#
import os
import sys
from pathlib import Path

# Bootstrap Django before importing any models.
#
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402

django.setup()

# Project imports
#
from django.conf import settings  # noqa: E402

from as_email.models import LocalDelivery  # noqa: E402

REPORT_FOLDERS = ("inbox", "Deleted Messages", "Junk", "Archive")


########################################################################
#
def disk_usage(path: Path) -> int:
    """Return total size in bytes of all files under `path`."""
    total = 0
    if not path.is_dir():
        return total
    for entry in path.rglob("*"):
        if entry.is_file():
            total += entry.stat().st_size
    return total


########################################################################
#
def count_messages(folder_path: Path) -> int:
    """
    Count MH messages in a folder. MH messages are files whose names
    are integers.
    """
    if not folder_path.is_dir():
        return 0
    return sum(
        1 for f in folder_path.iterdir() if f.is_file() and f.name.isdigit()
    )


########################################################################
#
def format_size(size_bytes: int) -> str:
    """Format a byte count into a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


########################################################################
#
def report_active_accounts() -> set[Path]:
    """
    Report usage for all active LocalDelivery accounts.
    Returns the set of maildir paths that are accounted for.
    """
    deliveries = LocalDelivery.objects.select_related(
        "email_account", "email_account__server"
    ).order_by(
        "email_account__server__domain_name", "email_account__email_address"
    )

    known_paths: set[Path] = set()

    if not deliveries.exists():
        print("No local delivery accounts found.")
        return known_paths

    current_domain = None

    for ld in deliveries:
        ea = ld.email_account
        domain = ea.server.domain_name
        maildir = Path(ld.maildir_path)
        known_paths.add(maildir)

        if domain != current_domain:
            if current_domain is not None:
                print()
            print(f"=== {domain} ===")
            current_domain = domain

        total_bytes = disk_usage(maildir)
        print(f"\n  {ea.email_address}  ({format_size(total_bytes)})")

        for folder_name in REPORT_FOLDERS:
            folder_path = maildir / folder_name
            msg_count = count_messages(folder_path)
            print(f"    {folder_name:<20s} {msg_count:>6d} messages")

    return known_paths


########################################################################
#
def report_orphaned_directories(known_paths: set[Path]) -> None:
    """
    Walk MAIL_DIRS and report any account directories that are not
    associated with a current LocalDelivery.

    The layout is: MAIL_DIRS / <domain> / <email_address> /
    We skip non-directory entries and the external password file.
    """
    mail_dirs = settings.MAIL_DIRS
    if not mail_dirs.is_dir():
        return

    orphans: list[tuple[str, str, int]] = []

    for domain_dir in sorted(mail_dirs.iterdir()):
        if not domain_dir.is_dir():
            continue
        for account_dir in sorted(domain_dir.iterdir()):
            if not account_dir.is_dir():
                continue
            if account_dir not in known_paths:
                orphans.append(
                    (domain_dir.name, account_dir.name, disk_usage(account_dir))
                )

    if not orphans:
        return

    total_orphan_bytes = sum(size for _, _, size in orphans)
    print(
        f"\n\n=== Orphaned mail directories ({format_size(total_orphan_bytes)} total) ==="
    )
    print(
        "These directories have no matching LocalDelivery and can be removed.\n"
    )

    current_domain = None
    for domain, account, size in orphans:
        if domain != current_domain:
            if current_domain is not None:
                print()
            print(f"  {domain}/")
            current_domain = domain
        print(f"    {account:<40s} {format_size(size):>10s}")


########################################################################
#
def main() -> None:
    known_paths = report_active_accounts()
    report_orphaned_directories(known_paths)


############################################################################
############################################################################
#
# Here is where it all starts
#
if __name__ == "__main__":
    main()
#
############################################################################
############################################################################
