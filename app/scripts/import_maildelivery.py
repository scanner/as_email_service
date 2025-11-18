#!/usr/bin/env python
#
"""
Read a mh slocal .maildelivery file and create Mesage Filter Rules based on
that file for the specified email account.
"""
# system imports
#
from pathlib import Path

# Project imports
#
from as_email.models import EmailAccount, MessageFilterRule


def run(*args):
    """
    Import a maildelivery file into message filter rules for an email
    account.  The first argument is the email account. The second argument is
    the maildelivery file to open.

    If an existing rule with the same "header" and "prefix" exists, it will be
    replaced.
    """
    if len(args) != 2:
        print(
            "Expected two arguments: email account, and location of maildelivery file"
        )
        return

    try:
        email_account = EmailAccount.objects.get(email_address=args[0])
    except EmailAccount.DoesNotExist:
        print("Email account '{email_account}' does not exist in the system.")
        return

    md_file = Path(args[1])
    if not (md_file.exists() and md_file.is_file()):
        print("Maildelivery file '{md_file}' must exist and be a file.")
        return

    with md_file.open() as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line[0] == "#":
                continue
            try:
                mfr = MessageFilterRule.create_from_rule(email_account, line)
            except Exception as e:
                print(f"Encountered exception {e}")
                print(f"while processing: '{line}'")
                return
            print(f"Created MFR: {mfr}")
