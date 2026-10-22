#!/usr/bin/env python3
"""
php_audit.py - scan a PHP codebase in response to CVE-2026-109618 / CVE-2026-109619 ("php2shell").

Checks:
  1. UPLOAD-PROGRESS  Does the app use session upload progress? (tells you if disabling
                      session.upload_progress.enabled will break anything)
  2. CONFIG           .user.ini / .htaccess / php.ini files in the tree that set
                      session.upload_progress.* (could re-enable it or matter later)
  3. WEBSHELL         Patterns typical of webshells / backdoors dropped after exploitation
  4. RISKY            Request data flowing straight into dangerous functions
  5. RECENT           PHP files created/modified since a given date (default: 2026-10-20)
  6. UPLOAD-DIR       PHP files sitting in upload/media directories

Stdlib only, Python 3.6+. Read-only: it never modifies anything.

Usage:
  python3 php_audit.py /var/www/app
  python3 php_audit.py /var/www/app --since 2026-10-19 --exclude vendor --exclude node_modules
  python3 php_audit.py /var/www/app --json > report.json

Exit code: 0 = nothing high-severity, 1 = high-severity findings, 2 = usage error.
"""

import argparse
import datetime as dt
import json
import os
import re
import sys

PHP_EXTS = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".pht", ".inc"}
TEMPLATE_EXTS = {".html", ".htm", ".tpl", ".twig", ".blade.php", ".js"}
CONFIG_NAMES = {".user.ini", ".htaccess", "php.ini"}
UPLOAD_DIR_NAMES = {"upload", "uploads", "files", "media", "images", "img", "tmp", "temp",
                    "cache", "attachments", "userfiles", "static", "assets"}
MAX_FILE_BYTES = 5 * 1024 * 1024
REQ = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)"

# (check, severity, label, regex)
CODE_RULES = [
    # 1. upload progress usage
    ("UPLOAD-PROGRESS", "info", "Uses upload progress name/key",
     r"PHP_SESSION_UPLOAD_PROGRESS|upload_progress_"),
    ("UPLOAD-PROGRESS", "info", "Reads/changes upload_progress ini setting",
     r"session\.upload_progress"),

    # 3. webshell / backdoor patterns
    ("WEBSHELL", "high", "eval of decoded data",
     r"eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|rawurldecode)\s*\("),
    ("WEBSHELL", "high", "eval/assert of request data",
     r"(?:eval|assert)\s*\(\s*(?:stripslashes\s*\(\s*)?" + REQ),
    ("WEBSHELL", "high", "Nested decode chain",
     r"(?:gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode\s*\("),
    ("WEBSHELL", "high", "preg_replace with /e modifier",
     r"preg_replace\s*\(\s*(['\"])(.).*?\2[a-zA-Z]*e[a-zA-Z]*\1"),
    ("WEBSHELL", "high", "Variable function called with request data",
     r"\$[A-Za-z_]\w*\s*\(\s*" + REQ + r"|" + REQ + r"\s*\[[^\]]+\]\s*\("),
    ("WEBSHELL", "high", "create_function with request data",
     r"create_function\s*\([^)]*" + REQ),
    ("WEBSHELL", "medium", "Very long base64-looking string",
     r"['\"][A-Za-z0-9+/=]{500,}['\"]"),
    ("WEBSHELL", "medium", "Error suppression + dynamic code",
     r"@\s*(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\("),
    ("WEBSHELL", "medium", "Obfuscated function name via chr()/concatenation",
     r"(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){4,}"),

    # 4. risky sinks fed by request data
    ("RISKY", "high", "OS command with request data",
     r"(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\([^;]*" + REQ),
    ("RISKY", "high", "Backtick shell with request data",
     r"`[^`]*" + REQ + r"[^`]*`"),
    ("RISKY", "high", "unserialize of request data",
     r"unserialize\s*\([^;]*" + REQ),
    ("RISKY", "high", "include/require with request data",
     r"(?:include|require)(?:_once)?\s*\(?[^;]*" + REQ),
    ("RISKY", "medium", "File write with request data",
     r"(?:file_put_contents|fwrite|fputs|move_uploaded_file)\s*\([^;]*" + REQ),
    ("RISKY", "low", "ini_set at runtime (note: cannot disable upload_progress)",
     r"ini_set\s*\(\s*['\"]session\.upload_progress"),
]
CODE_RULES = [(c, s, l, re.compile(r, re.IGNORECASE)) for c, s, l, r in CODE_RULES]

CONFIG_RULE = re.compile(r"session\.upload_progress\.[a-z_]+\s*[ =]\s*\S+", re.IGNORECASE)
CONFIG_ENABLED = re.compile(
    r"session\.upload_progress\.enabled\s*[ =]\s*['\"]?(1|on|true|yes)\b", re.IGNORECASE)
HTACCESS_PHP_HANDLER = re.compile(
    r"(AddType|AddHandler|SetHandler)\s+.*(php|x-httpd)", re.IGNORECASE)

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def parse_args():
    p = argparse.ArgumentParser(description="Audit a PHP codebase for php2shell exposure and compromise signs.")
    p.add_argument("root", help="Path to the PHP application root")
    p.add_argument("--since", default="2026-10-20",
                   help="Flag PHP files modified on/after this date (YYYY-MM-DD). Default: 2026-10-20")
    p.add_argument("--exclude", action="append", default=[],
                   help="Directory name to skip (repeatable), e.g. --exclude vendor")
    p.add_argument("--include-vendor", action="store_true",
                   help="Scan vendor/ and node_modules/ too (skipped by default)")
    p.add_argument("--json", action="store_true", help="Output JSON instead of text")
    p.add_argument("--max-line", type=int, default=160, help="Truncate matched lines to N chars")
    return p.parse_args()


def is_php(name):
    lower = name.lower()
    return os.path.splitext(lower)[1] in PHP_EXTS


def is_template(name):
    lower = name.lower()
    return any(lower.endswith(ext) for ext in TEMPLATE_EXTS)


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except (OSError, IOError):
        return None


def snippet(line, limit):
    line = line.strip()
    return line if len(line) <= limit else line[:limit] + " ..."


def scan_code(path, text, rules, max_line, findings):
    for lineno, line in enumerate(text.splitlines(), 1):
        for check, sev, label, rx in rules:
            if rx.search(line):
                findings.append({"check": check, "severity": sev, "label": label,
                                 "file": path, "line": lineno, "text": snippet(line, max_line)})


def scan_config(path, text, max_line, findings):
    name = os.path.basename(path).lower()
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith((";", "#")):
            continue
        if CONFIG_ENABLED.search(stripped):
            findings.append({"check": "CONFIG", "severity": "high",
                             "label": "Explicitly ENABLES session.upload_progress",
                             "file": path, "line": lineno, "text": snippet(line, max_line)})
        elif CONFIG_RULE.search(stripped):
            findings.append({"check": "CONFIG", "severity": "info",
                             "label": "Sets a session.upload_progress option",
                             "file": path, "line": lineno, "text": snippet(line, max_line)})
        if name == ".htaccess" and HTACCESS_PHP_HANDLER.search(stripped):
            findings.append({"check": "CONFIG", "severity": "medium",
                             "label": ".htaccess maps extra extensions to PHP (common backdoor trick)",
                             "file": path, "line": lineno, "text": snippet(line, max_line)})


def in_upload_dir(rel_path):
    parts = [p.lower() for p in rel_path.split(os.sep)[:-1]]
    return any(p in UPLOAD_DIR_NAMES for p in parts)


def main():
    args = parse_args()
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("Not a directory: %s" % root, file=sys.stderr)
        return 2
    try:
        since = dt.datetime.strptime(args.since, "%Y-%m-%d")
    except ValueError:
        print("--since must be YYYY-MM-DD", file=sys.stderr)
        return 2
    since_ts = since.timestamp()

    skip = set(args.exclude) | {".git", ".svn", ".hg"}
    if not args.include_vendor:
        skip |= {"vendor", "node_modules"}

    findings = []
    stats = {"php_files": 0, "config_files": 0, "template_files": 0, "skipped_large_or_unreadable": 0}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root)
            lower = fname.lower()

            if lower in CONFIG_NAMES or lower.endswith(".ini") or lower.endswith(".conf"):
                text = read_text(full)
                if text is None:
                    stats["skipped_large_or_unreadable"] += 1
                    continue
                if lower in CONFIG_NAMES or "upload_progress" in text:
                    stats["config_files"] += 1
                    scan_config(rel, text, args.max_line, findings)
                continue

            if is_php(fname):
                stats["php_files"] += 1
                text = read_text(full)
                if text is None:
                    stats["skipped_large_or_unreadable"] += 1
                else:
                    scan_code(rel, text, CODE_RULES, args.max_line, findings)

                try:
                    st = os.stat(full)
                    newest = max(st.st_mtime, st.st_ctime)
                    if newest >= since_ts:
                        when = dt.datetime.fromtimestamp(newest).strftime("%Y-%m-%d %H:%M")
                        findings.append({"check": "RECENT", "severity": "medium",
                                         "label": "PHP file changed since %s" % args.since,
                                         "file": rel, "line": 0, "text": "mtime/ctime %s" % when})
                except OSError:
                    pass

                if in_upload_dir(rel):
                    findings.append({"check": "UPLOAD-DIR", "severity": "high",
                                     "label": "PHP file inside an upload/media directory",
                                     "file": rel, "line": 0, "text": ""})
                continue

            if is_template(fname):
                text = read_text(full)
                if text and ("PHP_SESSION_UPLOAD_PROGRESS" in text or "upload_progress" in text):
                    stats["template_files"] += 1
                    scan_code(rel, text, CODE_RULES[:2], args.max_line, findings)

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["check"], f["file"], f["line"]))
    high = sum(1 for f in findings if f["severity"] == "high")
    uses_progress = any(f["check"] == "UPLOAD-PROGRESS" for f in findings)

    if args.json:
        print(json.dumps({"root": root, "since": args.since, "stats": stats,
                          "uses_upload_progress": uses_progress,
                          "high_severity_count": high, "findings": findings}, indent=2))
    else:
        print("PHP audit: %s" % root)
        print("Scanned %d PHP files, %d config files (%d skipped)\n"
              % (stats["php_files"], stats["config_files"], stats["skipped_large_or_unreadable"]))
        if uses_progress:
            print("!! The app appears to USE session upload progress. Disabling\n"
                  "   session.upload_progress.enabled will stop progress reporting\n"
                  "   (uploads still work). Review the UPLOAD-PROGRESS hits below.\n")
        else:
            print("OK: no use of session upload progress found - safe to disable it.\n")

        if not findings:
            print("No findings.")
        current = None
        for f in findings:
            key = (f["severity"], f["check"])
            if key != current:
                current = key
                print("\n[%s] %s" % (f["severity"].upper(), f["check"]))
            loc = f["file"] if not f["line"] else "%s:%d" % (f["file"], f["line"])
            print("  - %s  (%s)" % (loc, f["label"]))
            if f["text"]:
                print("      %s" % f["text"])
        print("\nSummary: %d findings, %d high severity." % (len(findings), high))
        print("Note: pattern matching gives false positives and can miss obfuscated code;\n"
              "treat hits as leads to review, not verdicts.")

    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
