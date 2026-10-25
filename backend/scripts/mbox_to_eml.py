"""
Split an mbox file (optionally .gz) into one .eml file per message.

Usage:
    python scripts/mbox_to_eml.py phishing-2025 out/phishing --max 300
    python scripts/mbox_to_eml.py httpd-dev-2025-09.mbox out/legit --skip-existing ../datasets

Files are named by the first 16 characters of their SHA-256, so the same
email is never written twice, and --skip-existing leaves out any email that
already appears (same bytes) anywhere under the given folder, e.g. your old
dev/test sets.
"""

import argparse
import gzip
import hashlib
import mailbox
import os
import random
import shutil
import tempfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def known_hashes(folder):
    hashes = set()
    for root, _, files in os.walk(folder):
        for name in files:
            if name.lower().endswith(".eml"):
                with open(os.path.join(root, name), "rb") as fh:
                    hashes.add(sha(fh.read()))
    return hashes


def open_mbox(path):
    if path.endswith(".gz"):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".mbox")
        with gzip.open(path, "rb") as src, tmp:
            shutil.copyfileobj(src, tmp)
        return mailbox.mbox(tmp.name), tmp.name
    return mailbox.mbox(path), None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mbox")
    ap.add_argument("out_dir")
    ap.add_argument("--max", type=int, default=0, help="keep at most N messages (random sample)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip-existing", metavar="FOLDER", help="skip emails already in this folder tree")
    args = ap.parse_args()

    box, tmp = open_mbox(args.mbox)
    skip = known_hashes(args.skip_existing) if args.skip_existing else set()
    os.makedirs(args.out_dir, exist_ok=True)

    messages = []
    seen = set()
    skipped = 0
    for msg in box:
        data = msg.as_bytes()
        digest = sha(data)
        if digest in skip:
            skipped += 1
            continue
        if digest in seen:
            continue
        seen.add(digest)
        messages.append((digest, data))

    if args.max and len(messages) > args.max:
        random.Random(args.seed).shuffle(messages)
        messages = messages[: args.max]

    for digest, data in messages:
        with open(os.path.join(args.out_dir, digest[:16] + ".eml"), "wb") as fh:
            fh.write(data)

    if tmp:
        os.remove(tmp)
    print(f"Wrote {len(messages)} .eml files to {args.out_dir} "
          f"(skipped {skipped} already in --skip-existing).")


if __name__ == "__main__":
    main()
