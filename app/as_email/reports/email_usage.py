#!/usr/bin/env python
#
"""
Generate a mailbox usage report for all email accounts with local delivery.

Enumerates all LocalDelivery instances, counts messages per folder
(Inbox, Deleted Messages, Junk, Archive), and calculates total disk
usage per account. Also detects orphaned mail directories — both for
accounts whose LocalDelivery was removed and for entire domain
directories whose Server no longer exists in the database.
"""

# system imports
#
from pathlib import Path

# 3rd party imports
#
from django.conf import settings

# Project imports
#
from as_email.models import LocalDelivery, Server

REPORT_FOLDERS = ("inbox", "Deleted Messages", "Junk", "Archive")


########################################################################
#
def _disk_usage(path: Path) -> int:
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
def _count_messages(folder_path: Path) -> int:
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
def _format_size(size_bytes: int) -> str:
    """Format a byte count into a human-readable string."""
    size: float = size_bytes
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


########################################################################
#
def _report_active_accounts(lines: list[str]) -> set[Path]:
    """
    Append per-account usage lines for all active LocalDelivery accounts.
    Returns the set of maildir paths that are accounted for.
    """
    deliveries = LocalDelivery.objects.select_related(
        "email_account", "email_account__server"
    ).order_by(
        "email_account__server__domain_name", "email_account__email_address"
    )

    known_paths: set[Path] = set()

    if not deliveries.exists():
        lines.append("No local delivery accounts found.")
        return known_paths

    current_domain = None

    for ld in deliveries:
        ea = ld.email_account
        domain = ea.server.domain_name
        if not ld.maildir_path:
            continue
        maildir = Path(ld.maildir_path)
        known_paths.add(maildir)

        if domain != current_domain:
            if current_domain is not None:
                lines.append("")
            lines.append(f"=== {domain} ===")
            current_domain = domain

        total_bytes = _disk_usage(maildir)
        lines.append(f"\n  {ea.email_address}  ({_format_size(total_bytes)})")

        for folder_name in REPORT_FOLDERS:
            folder_path = maildir / folder_name
            msg_count = _count_messages(folder_path)
            lines.append(f"    {folder_name:<20s} {msg_count:>6d} messages")

    return known_paths


########################################################################
#
def _report_orphaned_directories(
    lines: list[str], known_paths: set[Path]
) -> None:
    """
    Walk MAIL_DIRS and report mail directories that are not associated
    with a current LocalDelivery or Server.

    Detects two kinds of orphans:
    - Domain directories (MAIL_DIRS/<domain>/) with no matching Server
    - Account directories (MAIL_DIRS/<domain>/<email>/) with no matching
      LocalDelivery
    """
    mail_dirs: Path = settings.MAIL_DIRS
    if not mail_dirs.is_dir():
        return

    known_domains = set(Server.objects.values_list("domain_name", flat=True))

    orphaned_domains: list[tuple[str, int]] = []
    orphaned_accounts: list[tuple[str, str, int]] = []

    for domain_dir in sorted(mail_dirs.iterdir()):
        if not domain_dir.is_dir():
            continue

        if domain_dir.name not in known_domains:
            orphaned_domains.append((domain_dir.name, _disk_usage(domain_dir)))
            continue

        for account_dir in sorted(domain_dir.iterdir()):
            if not account_dir.is_dir():
                continue
            if account_dir not in known_paths:
                orphaned_accounts.append(
                    (
                        domain_dir.name,
                        account_dir.name,
                        _disk_usage(account_dir),
                    )
                )

    if orphaned_domains:
        total_bytes = sum(size for _, size in orphaned_domains)
        lines.append("")
        lines.append(
            f"=== Orphaned domain directories "
            f"({_format_size(total_bytes)} total) ==="
        )
        lines.append(
            "These domain directories have no matching Server "
            "and can be removed."
        )
        lines.append("")
        for domain, size in orphaned_domains:
            lines.append(f"  {domain + '/': <44s} {_format_size(size):>10s}")

    if orphaned_accounts:
        total_bytes = sum(size for _, _, size in orphaned_accounts)
        lines.append("")
        lines.append(
            f"=== Orphaned account directories "
            f"({_format_size(total_bytes)} total) ==="
        )
        lines.append(
            "These account directories have no matching LocalDelivery "
            "and can be removed."
        )
        lines.append("")
        current_domain = None
        for domain, account, size in orphaned_accounts:
            if domain != current_domain:
                if current_domain is not None:
                    lines.append("")
                lines.append(f"  {domain}/")
                current_domain = domain
            lines.append(f"    {account:<40s} {_format_size(size):>10s}")


########################################################################
#
def generate_email_usage_report() -> str:
    """
    Generate a full email usage report as a string.

    The report includes:
    - Per-account message counts and disk usage for active LocalDelivery
      accounts, grouped by domain
    - Orphaned domain directories with no matching Server in the database
    - Orphaned account directories with no matching LocalDelivery

    Returns:
        The complete report as a single string.
    """
    lines: list[str] = []
    lines.append("Email Account Usage Report")
    lines.append("=" * 40)
    lines.append("")

    known_paths = _report_active_accounts(lines)
    _report_orphaned_directories(lines, known_paths)

    lines.append("")
    return "\n".join(lines)
