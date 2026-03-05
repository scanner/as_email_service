#!/usr/bin/env python
#
"""
Read messages from files as strings.
Encode them in an EmailMessage.
Decode them to string. Look for unicode errors.
"""
import email
import email.policy
import sys
from pathlib import Path


def _string_to_bytes(message):
    # If a message is not 7bit clean, we refuse to handle it since it
    # likely came from reading invalid messages in text mode, and that way
    # lies mojibake.
    try:
        return message.encode("ascii")
    except UnicodeError:
        raise ValueError(
            "String input must be ASCII-only; " "use bytes or a Message instead"
        )


#############################################################################
#
def main():
    """
    go through all messages in the given folder, recursively. Read them as
    strings.
    Parse them in to EmailMessage,
    then dump them again as a string.
    """
    top_dir = Path(sys.argv[1])
    print(f"Looking at messages in '{top_dir}'")
    bad_charsets = []
    try:
        for dir_path, dir_names, file_names in top_dir.walk():
            file_names = sorted(
                [x for x in file_names if x.isnumeric()], key=lambda x: int(x)
            )
            for file_name in file_names:
                msg_text = (dir_path / file_name).read_bytes()
                msg = email.message_from_bytes(
                    msg_text, policy=email.policy.default
                )
                try:
                    msg_text = msg.as_string(policy=email.policy.default)
                except Exception as e:
                    bad_charsets.append(
                        f"*** Unable to parse message as string: {dir_path / file_name}: {e}"
                    )
                # try:
                #     msg_binary = _string_to_bytes(msg_text)
                # except Exception as e:
                #     print(f"\nUnable to use string to bytes on {dir_path / file_name}: {e}")
                try:
                    msg_binary = msg.as_bytes(policy=email.policy.default)
                except Exception as e:
                    print(
                        f"Unable to use as_bytes on {dir_path / file_name}: {e}"
                    )
                    raise

                print(".", sep="", end="", flush=True)
                assert msg_binary
    finally:
        for b in bad_charsets:
            print(b)


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
