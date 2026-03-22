#!/usr/bin/env python
#
"""
Extract original spam messages from forwarded emails for training SpamAssassin.

When users forward spam to a spam bucket, the original spam message is typically
attached as a message/rfc822 MIME part. This script extracts those original
messages and moves processed messages out of the source directory.

Usage:
    extract_forwarded_spam.py <input_dir> <output_dir>
    extract_forwarded_spam.py -h | --help

Arguments:
    <input_dir>     Directory containing forwarded spam messages
    <output_dir>    Directory where extracted spam will be saved

Options:
    -h --help       Show this help message

Examples:
    # Extract forwarded spam messages
    python extract_forwarded_spam.py ./spam_bucket ./training/spam

Notes:
    - Messages with message/rfc822 attachments will have the attachment extracted
    - Messages without attachments are copied as-is
    - Successfully processed messages are deleted from input_dir
"""

# system imports
#
import email
import sys
from email import policy
from pathlib import Path

# 3rd party imports
#
from docopt import docopt


####################################################################
#
def extract_forwarded_message(msg_path: Path, output_dir: Path) -> bool:
    """
    Extract the original message from a forwarded email and save it.

    If the message contains a message/rfc822 attachment (forwarded message),
    extract and save it. Otherwise, copy the original message as-is.

    Returns True on success, False on error.
    """
    try:
        # Read the forwarded message
        msg_bytes = msg_path.read_bytes()
        msg = email.message_from_bytes(msg_bytes, policy=policy.default)

        # Look for message/rfc822 attachments (forwarded messages)
        extracted = False
        for part in msg.walk():
            if part.get_content_type() == "message/rfc822":
                # Extract the attached message
                attached_msg = part.get_payload(0)

                # Generate output filename
                output_path = (
                    output_dir / f"{msg_path.stem}_extracted{msg_path.suffix}"
                )

                # Write the extracted message
                output_path.write_bytes(attached_msg.as_bytes())
                print(f"Extracted: {msg_path.name} -> {output_path.name}")
                extracted = True
                break

        if not extracted:
            # No forwarded message found, copy the original
            # (might be an inline forward or direct spam)
            output_path = output_dir / msg_path.name
            output_path.write_bytes(msg_bytes)
            print(f"No attachment, copied original: {msg_path.name}")

        return True

    except Exception as e:
        print(f"Error processing {msg_path}: {e}", file=sys.stderr)
        return False


####################################################################
#
def process_spam_bucket(input_dir: Path, output_dir: Path) -> int:
    """
    Process all messages in the spam bucket.

    Extract forwarded messages and delete successfully processed files
    from the input directory.

    Returns the number of successfully processed messages.
    """
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)

    # Get all files in input directory
    email_files = [f for f in input_dir.iterdir() if f.is_file()]

    if not email_files:
        print(f"No files found in {input_dir}")
        return 0

    print(f"Processing {len(email_files)} files...")
    success_count = 0

    for email_file in email_files:
        # Extract/copy the message
        if extract_forwarded_message(email_file, output_dir):
            success_count += 1
            # Delete the source file after successful processing
            try:
                email_file.unlink()
                print(f"Deleted source: {email_file.name}")
            except Exception as e:
                print(
                    f"Warning: Could not delete {email_file.name}: {e}",
                    file=sys.stderr,
                )

    return success_count


####################################################################
#
def main():
    """
    Main entry point for the script.
    """
    args = docopt(__doc__)

    input_dir = Path(args["<input_dir>"])
    output_dir = Path(args["<output_dir>"])

    # Validate input directory
    if not input_dir.is_dir():
        print(
            f"Error: Input directory does not exist: {input_dir}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Process the spam bucket
    success_count = process_spam_bucket(input_dir, output_dir)

    print(f"\nProcessed {success_count} files successfully")
    print(f"Extracted messages saved to: {output_dir}")


if __name__ == "__main__":
    main()
