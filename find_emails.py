#!/usr/bin/env python3
"""
find_emails.py - find email addresses in PHP and Python source code.

Lists every unique address with all its locations, grouped by domain, and marks
whether each hit sits in a comment or in code/strings. Skips common false positives
(image names like logo@2x.png, package specs like pkg@1.2.3), and reports
placeholder addresses (example.com, test, localhost...) separately.
Also flags URLs with embedded credentials (scheme://user:password@host), since
those turn up in the same search.

Stdlib only, Python 3.6+, read-only.

Usage:
  python3 find_emails.py /path/to/src
  python3 find_emails.py /path/to/src --ext .html --ext .js     # also scan these
  python3 find_emails.py /path/to/src --domain mycompany.lv      # only this domain
  python3 find_emails.py /path/to/src --csv emails.csv
  python3 find_emails.py /path/to/src --json > emails.json
  python3 find_emails.py /path/to/src --include-placeholders     # list them with the rest
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict

DEFAULT_EXTS = {".php", ".phtml", ".inc", ".py", ".pyw"}
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv", "env",
             "site-packages", ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode"}
MAX_FILE_BYTES = 5 * 1024 * 1024

EMAIL_RE = re.compile(
    r"(?<![\w.%+\-/])"                         # not glued to a longer token
    r"([A-Za-z0-9][A-Za-z0-9._%+\-]{0,63})"   # local part
    r"@"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})"  # domain
    r"(?![\w\-]|\.[A-Za-z])"
)
URL_CREDS_RE = re.compile(r"\b([a-z][a-z0-9+.\-]*)://([^\s:/@'\"]+):([^\s/@'\"]+)@([A-Za-z0-9.\-]+)", re.I)

FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "css", "js", "map", "min", "json",
             "php", "py", "html", "htm", "txt", "md", "xml", "pdf", "zip", "gz", "tar", "woff", "woff2", "ttf"}
PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "domain.com", "email.com", "mail.com",
                       "test.com", "test.test", "localhost.localdomain", "yourdomain.com", "company.com",
                       "mydomain.com", "somedomain.com", "foo.com", "bar.com", "foo.bar", "acme.com"}
PLACEHOLDER_TLDS = {"test", "example", "invalid", "localhost", "local"}


def is_placeholder(local, domain):
    d = domain.lower()
    if d in PLACEHOLDER_DOMAINS or d.rsplit(".", 1)[-1] in PLACEHOLDER_TLDS:
        return True
    if any(d.endswith("." + p) for p in PLACEHOLDER_DOMAINS):
        return True
    return local.lower() in {"user", "username", "your.email", "youremail", "someone"} and "example" in d


def classify(line, col, ext):
    """Return 'comment' if position col sits in a line comment / docblock line, else 'code'."""
    stripped = line.lstrip()
    if ext in (".py", ".pyw"):
        if stripped.startswith("#"):
            return "comment"
    else:
        if stripped.startswith(("//", "#", "*", "/*")):
            return "comment"
    # trailing comment: a comment marker before col that is not inside quotes
    quote = None
    i = 0
    while i < col:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" or (ext not in (".py", ".pyw") and line.startswith("//", i)):
            return "comment"
        i += 1
    return "code"


def scan(root, exts, skip, domain_filter):
    hits = defaultdict(list)          # email -> [(file, line, context, text)]
    creds = []
    nfiles = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for fn in sorted(filenames):
            ext = os.path.splitext(fn)[1].lower()
            if ext not in exts:
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                with open(path, "rb") as fh:
                    text = fh.read().decode("utf-8", errors="replace")
            except OSError:
                continue
            nfiles += 1
            for ln, line in enumerate(text.splitlines(), 1):
                if "@" not in line:
                    continue
                for m in URL_CREDS_RE.finditer(line):
                    creds.append((rel, ln, "%s://%s:****@%s" % (m.group(1), m.group(2), m.group(4))))
                for m in EMAIL_RE.finditer(line):
                    local, domain = m.group(1), m.group(2)
                    tld = domain.rsplit(".", 1)[-1].lower()
                    if tld in FILE_TLDS:
                        continue                      # logo@2x.png, jquery@3.6.min.js
                    if re.match(r"^\d+(\.\d+)*$", domain.rsplit(".", 1)[0]):
                        continue                      # pkg@1.2.3-style
                    before = line[:m.start()]
                    if re.search(r"://[^\s/@]*:[^\s/@]*$", before):
                        continue                      # password@host from a credentials URL
                    if domain_filter and not (domain.lower() == domain_filter or
                                              domain.lower().endswith("." + domain_filter)):
                        continue
                    email = (local + "@" + domain).lower()
                    hits[email].append((rel, ln, classify(line, m.start(), ext), line.strip()[:160]))
    return hits, creds, nfiles


def main():
    p = argparse.ArgumentParser(description="Find email addresses in PHP and Python source code.")
    p.add_argument("root")
    p.add_argument("--ext", action="append", default=[], help="Extra file extension to scan, e.g. --ext .html")
    p.add_argument("--exclude", action="append", default=[], help="Directory name to skip (repeatable)")
    p.add_argument("--include-vendor", action="store_true", help="Also scan vendor/ (skipped by default)")
    p.add_argument("--domain", help="Only report addresses in this domain (and its subdomains)")
    p.add_argument("--include-placeholders", action="store_true",
                   help="List example.com/test addresses together with the real ones")
    p.add_argument("--max-locations", type=int, default=5, help="Locations shown per address (0 = all)")
    p.add_argument("--csv", metavar="FILE", help="Write every hit to CSV")
    p.add_argument("--json", action="store_true", help="Print JSON instead of text")
    args = p.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("Not a directory: %s" % root, file=sys.stderr)
        return 2
    exts = DEFAULT_EXTS | {e.lower() if e.startswith(".") else "." + e.lower() for e in args.ext}
    skip = SKIP_DIRS | set(args.exclude)
    if not args.include_vendor:
        skip.add("vendor")
    domain_filter = args.domain.lower().lstrip("@") if args.domain else None

    hits, creds, nfiles = scan(root, exts, skip, domain_filter)

    real, placeholders = {}, {}
    for email, locs in hits.items():
        local, domain = email.split("@", 1)
        (placeholders if is_placeholder(local, domain) and not args.include_placeholders else real)[email] = locs

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["email", "domain", "placeholder", "file", "line", "context", "code"])
            for group, flag in ((real, "no"), (placeholders, "yes")):
                for email in sorted(group):
                    for f, ln, ctx, txt in group[email]:
                        w.writerow([email, email.split("@", 1)[1], flag, f, ln, ctx, txt])

    if args.json:
        print(json.dumps({
            "root": root, "files_scanned": nfiles,
            "emails": [{"email": e, "domain": e.split("@", 1)[1], "count": len(l),
                        "locations": [{"file": f, "line": ln, "context": c, "code": t} for f, ln, c, t in l]}
                       for e, l in sorted(real.items())],
            "placeholders": sorted(placeholders),
            "url_credentials": [{"file": f, "line": ln, "url": u} for f, ln, u in creds],
        }, indent=2))
        return 0

    w = sys.stdout.write
    w("Email scan: %s\n" % root)
    w("Scanned %d files (%s)%s\n" % (nfiles, " ".join(sorted(exts)),
                                     "" if args.include_vendor else ", vendor/ skipped"))
    total = sum(len(l) for l in real.values())
    w("Found %d unique address(es), %d occurrence(s)%s\n"
      % (len(real), total, (", plus %d placeholder(s)" % len(placeholders)) if placeholders else ""))

    by_domain = defaultdict(list)
    for email in real:
        by_domain[email.split("@", 1)[1]].append(email)
    for domain in sorted(by_domain, key=lambda d: (-sum(len(real[e]) for e in by_domain[d]), d)):
        emails = sorted(by_domain[domain])
        w("\n@%s  (%d address(es))\n" % (domain, len(emails)))
        for email in emails:
            locs = real[email]
            in_code = sum(1 for l in locs if l[2] == "code")
            w("  %s  - %d hit(s)%s\n" % (email, len(locs),
                                         "" if in_code == len(locs) else ", %d in comments" % (len(locs) - in_code)))
            shown = locs if args.max_locations == 0 else locs[:args.max_locations]
            for f, ln, ctx, txt in shown:
                w("      %s:%d%s  %s\n" % (f, ln, " [comment]" if ctx == "comment" else "", txt[:110]))
            if len(shown) < len(locs):
                w("      ... %d more\n" % (len(locs) - len(shown)))

    if placeholders:
        w("\nPlaceholder/test addresses (use --include-placeholders for locations):\n  %s\n"
          % ", ".join(sorted(placeholders)[:30]) + ("  ...\n" if len(placeholders) > 30 else ""))
    if creds:
        w("\n!! URLs with embedded credentials (password masked) - move these to config/secrets:\n")
        for f, ln, u in creds[:30]:
            w("  %s:%d  %s\n" % (f, ln, u))
    if args.csv:
        w("\nCSV written to %s\n" % args.csv)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:          # output piped into head/less that closed early
        sys.stderr.close()
        sys.exit(0)
