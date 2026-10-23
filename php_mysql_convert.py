#!/usr/bin/env python3
"""
php_mysql_convert.py - mechanically convert legacy PHP code:

  * mysql_*  ->  mysqli_*   (adds the connection argument, swaps argument order,
                             renames MYSQL_ASSOC/NUM/BOTH constants)
  * split / spliti / ereg / eregi / ereg_replace / eregi_replace
             ->  explode / preg_split / preg_match / preg_replace
  * while (list($k, $v) = each($arr))  ->  foreach ($arr as $k => $v)
  * implode($array, ', ')  ->  implode(', ', $array)      (argument order, removed in 8.0)
  * <?  (short open tag)   ->  <?php

The converted code runs on PHP 5.6 AND PHP 7/8, so you can convert, deploy and test
on your current 5.6 server first, then switch the PHP version as a separate step.

How the connection is handled
  mysql_* functions silently used "the last opened connection". The converted code uses
  $GLOBALS['mysql_link'] for that (works inside functions without 'global' statements).
  mysql_connect()/mysql_pconnect() become mysql_compat_connect(), a small helper (written
  to mysql_compat.php with --apply) that opens the mysqli connection, stores it in
  $GLOBALS['mysql_link'], understands "host:port", and keeps mysql-style error handling
  (returns false instead of throwing). Calls that passed an explicit link keep using it.
  mysql_result() becomes mysql_compat_result() from the same helper file.

Safety
  * Default is a dry run: prints a summary, writes a unified diff (mysql_convert.patch).
  * --apply changes files in place and first copies every changed file to a backup
    directory OUTSIDE the project (default: <project>.bak-<timestamp>).
  * Only code is touched: comments, strings, heredocs and inline HTML are left alone.
  * Files are processed byte-exact, so non-UTF-8 legacy files (latin-1, cp1257...) and
    CRLF line endings survive unchanged.
  * Anything without a safe 1:1 conversion is listed for manual work instead of guessed.

Stdlib only, Python 3.6+.

Usage:
  python3 php_mysql_convert.py /path/to/app                       # dry run + patch file
  python3 php_mysql_convert.py /path/to/app --exclude Pear        # skip a directory
  python3 php_mysql_convert.py /path/to/app --only mysql,each     # pick: mysql,regex,each,implode,tags
  python3 php_mysql_convert.py /path/to/app --apply               # write changes + backups
"""

import argparse
import bisect
import datetime
import difflib
import os
import re
import shutil
import sys
from collections import Counter, defaultdict

PHP_EXTS = (".php", ".phtml", ".php3", ".php4", ".php5", ".inc")
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules"}
MAX_FILE_BYTES = 8 * 1024 * 1024
STR = "\x01"
ENC = "latin-1"          # byte-transparent: every byte maps to one char and back

# ======================================================================================
# PHP-aware masking: comments / inline HTML -> spaces, string contents -> STR.
# Same length as the input, so offsets map 1:1 to the original text.
# ======================================================================================
HEREDOC_RE = re.compile(r"<<<[ \t]*([\"']?)([A-Za-z_]\w*)\1[ \t]*\r?\n")
OPEN_TAG_RE = re.compile(r"<\?(php\b|=)?", re.IGNORECASE)
PHP_TOKEN_RE = re.compile(r"\?>|#|//|/\*|['\"`]|<<<")
LINE_COMMENT_RE = re.compile(r"[^\n?]*(?:\?(?!>)[^\n?]*)*")
STRING_RES = {q: re.compile(q + r"[^" + q + r"\\]*(?:\\.[^" + q + r"\\]*)*" + q, re.S) for q in "'\"`"}
NON_NL_RE = re.compile(r"[^\n]")


def _fill(seg, ch=" "):
    return NON_NL_RE.sub(ch, seg)


def mask_php(src, short_tags=None):
    parts, n, i, in_php = [], len(src), 0, False
    while i < n:
        if not in_php:
            j = src.find("<?", i)
            if j < 0:
                parts.append(_fill(src[i:]))
                break
            parts.append(_fill(src[i:j]))
            if src[j:j + 5].lower() == "<?xml":
                parts.append(_fill(src[j:j + 5]))
                i = j + 5
                continue
            m = OPEN_TAG_RE.match(src, j)
            if short_tags is not None and not m.group(1):
                short_tags.append(j)
            parts.append(_fill(src[j:m.end()]))
            i, in_php = m.end(), True
            continue
        m = PHP_TOKEN_RE.search(src, i)
        if not m:
            parts.append(src[i:])
            break
        parts.append(src[i:m.start()])
        i, tok = m.start(), m.group()
        if tok == "?>":
            parts.append("  ")
            i += 2
            in_php = False
        elif tok in ("#", "//"):
            e = LINE_COMMENT_RE.match(src, i + len(tok)).end()
            parts.append(_fill(src[i:e]))
            i = e
        elif tok == "/*":
            e = src.find("*/", i + 2)
            e = n if e < 0 else e + 2
            parts.append(_fill(src[i:e]))
            i = e
        elif tok == "<<<":
            hm = HEREDOC_RE.match(src, i)
            if not hm:
                parts.append(tok)
                i += 3
                continue
            parts.append(src[i:hm.end()])
            end = re.compile(r"^[ \t]*" + re.escape(hm.group(2)) + r"\b", re.M).search(src, hm.end())
            body_end = end.start() if end else n
            parts.append(_fill(src[hm.end():body_end], STR))
            i = body_end
        else:
            sm = STRING_RES[tok].match(src, i)
            e = sm.end() if sm else n
            close = tok if sm else ""
            parts.append(tok + _fill(src[i + 1:e - len(close)], STR) + close)
            i = e
    out = "".join(parts)
    assert len(out) == n
    return out


def match_parens(text, open_idx):
    depth = 0
    for k in range(open_idx, len(text)):
        ch = text[k]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return k
    return -1


def arg_spans(masked, a, b):
    """Top-level comma-separated argument spans within masked[a:b], whitespace-trimmed."""
    spans, depth, start = [], 0, a
    for k in range(a, b):
        ch = masked[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((start, k))
            start = k + 1
    spans.append((start, b))
    out = []
    for s, e in spans:
        while s < e and masked[s].isspace():
            s += 1
        while e > s and masked[e - 1].isspace():
            e -= 1
        out.append((s, e))
    if len(out) == 1 and out[0][0] == out[0][1]:
        return []
    return out


# ======================================================================================
# Conversion tables
# ======================================================================================
RESULT_RENAME = {   # same arguments, result first
    "mysql_fetch_assoc": "mysqli_fetch_assoc", "mysql_fetch_array": "mysqli_fetch_array",
    "mysql_fetch_row": "mysqli_fetch_row", "mysql_fetch_object": "mysqli_fetch_object",
    "mysql_num_rows": "mysqli_num_rows", "mysql_numrows": "mysqli_num_rows",
    "mysql_num_fields": "mysqli_num_fields", "mysql_numfields": "mysqli_num_fields",
    "mysql_free_result": "mysqli_free_result", "mysql_freeresult": "mysqli_free_result",
    "mysql_data_seek": "mysqli_data_seek", "mysql_fetch_lengths": "mysqli_fetch_lengths",
    "mysql_field_seek": "mysqli_field_seek",
    "mysql_result": "mysql_compat_result",          # helpers: also work when the connect itself failed
    "mysql_error": "mysql_compat_error",
    "mysql_errno": "mysql_compat_errno",
    "mysql_get_client_info": "mysqli_get_client_info",
}
LINK_ONLY = {       # f([link])  ->  mysqli_f(link)
    "mysql_insert_id": "mysqli_insert_id", "mysql_affected_rows": "mysqli_affected_rows",
    "mysql_close": "mysqli_close",
    "mysql_info": "mysqli_info", "mysql_ping": "mysqli_ping", "mysql_thread_id": "mysqli_thread_id",
    "mysql_stat": "mysqli_stat", "mysql_get_host_info": "mysqli_get_host_info",
    "mysql_get_proto_info": "mysqli_get_proto_info", "mysql_get_server_info": "mysqli_get_server_info",
    "mysql_client_encoding": "mysqli_character_set_name",
}
LINK_LAST = {       # f(x[, link])  ->  mysqli_f(link, x[, extra])   (new name, link allowed, extra arg)
    "mysql_query": ("mysqli_query", True, None),
    "mysql_unbuffered_query": ("mysqli_query", True, "MYSQLI_USE_RESULT"),
    "mysql_real_escape_string": ("mysqli_real_escape_string", True, None),
    "mysql_escape_string": ("mysqli_real_escape_string", False, None),
    "mysql_select_db": ("mysqli_select_db", True, None),
    "mysql_selectdb": ("mysqli_select_db", True, None),
    "mysql_set_charset": ("mysqli_set_charset", True, None),
}
FIELD_PROPS = {     # f($result, $i)  ->  mysqli_fetch_field_direct($result, $i)->prop
    "mysql_field_name": "name", "mysql_fieldname": "name",
    "mysql_field_len": "length", "mysql_fieldlen": "length",
    "mysql_field_table": "table", "mysql_fieldtable": "table",
}
CONNECT = {"mysql_connect": False, "mysql_pconnect": True}
MANUAL_REASON = {
    "mysql_db_query": "select the DB with mysqli_select_db(), then mysqli_query()",
    "mysql_list_tables": "use mysqli_query($link, 'SHOW TABLES FROM db')",
    "mysql_list_dbs": "use mysqli_query($link, 'SHOW DATABASES')",
    "mysql_list_fields": "use mysqli_query($link, 'SHOW COLUMNS FROM table')",
    "mysql_list_processes": "use mysqli_query($link, 'SHOW PROCESSLIST')",
    "mysql_db_name": "read the row from the SHOW DATABASES result instead",
    "mysql_dbname": "read the row from the SHOW DATABASES result instead",
    "mysql_tablename": "read the row from the SHOW TABLES result instead",
    "mysql_table_name": "read the row from the SHOW TABLES result instead",
    "mysql_fetch_field": "mysqli_fetch_field()/mysqli_fetch_field_direct() - object properties differ",
    "mysql_field_type": "mysqli_fetch_field_direct()->type is a number, not a type name",
    "mysql_field_flags": "mysqli_fetch_field_direct()->flags is a bitmask, not a string",
    "mysql_create_db": "use mysqli_query($link, 'CREATE DATABASE ...')",
    "mysql_createdb": "use mysqli_query($link, 'CREATE DATABASE ...')",
    "mysql_drop_db": "use mysqli_query($link, 'DROP DATABASE ...')",
    "mysql_dropdb": "use mysqli_query($link, 'DROP DATABASE ...')",
}
KNOWN_MYSQL = set(RESULT_RENAME) | set(LINK_ONLY) | set(LINK_LAST) | set(FIELD_PROPS) | set(CONNECT) | set(MANUAL_REASON)
REGEX_FUNCS = {"split": (False, "split"), "spliti": (True, "split"), "ereg": (False, "match"),
               "eregi": (True, "match"), "ereg_replace": (False, "replace"), "eregi_replace": (True, "replace")}

CALL_RE = re.compile(r"(?<![\w$>:])(\\?)\b(mysql_\w+|split|spliti|ereg|eregi|ereg_replace|eregi_replace)\s*\(",
                     re.IGNORECASE)
CONST_RE = re.compile(r"(?<![\w$>:\\])MYSQL_(ASSOC|NUM|BOTH)\b")
DEF_RE = re.compile(r"^\s*function\s+&?\s*(\w+)\s*\(", re.M | re.I)

# ======================================================================================
# PHP string literal helpers (for regex patterns)
# ======================================================================================
DQ_ESC = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f", "e": "\x1b", "\\": "\\", '"': '"', "$": "$"}


def literal_arg(raw, masked, s, e):
    """Decoded value of a plain string-literal argument, or None."""
    text, m = raw[s:e], masked[s:e]
    if len(text) < 2 or text[0] not in "'\"" or text[-1] != text[0] or m[0] != text[0] or m[-1] != text[0]:
        return None
    if any(ch not in (STR, "\n", "\r") for ch in m[1:-1]):
        return None              # concatenation like 'a' . $x . 'b'
    inner = text[1:-1]
    if text[0] == "'":
        return re.sub(r"\\([\\'])", r"\1", inner)
    out, i = [], 0
    while i < len(inner):
        ch = inner[i]
        if ch == "\\" and i + 1 < len(inner):
            nxt = inner[i + 1]
            if nxt in DQ_ESC:
                out.append(DQ_ESC[nxt])
                i += 2
                continue
            if nxt in "xu01234567":
                return None      # hex/octal/unicode escapes: leave for a human
            out.append(ch)
            i += 1
            continue
        if ch == "$" or (ch == "{" and inner[i + 1:i + 2] == "$"):
            return None          # interpolated variable
        out.append(ch)
        i += 1
    return "".join(out)


def is_string_literal(raw, masked, s, e):
    text, m = raw[s:e], masked[s:e]
    return (len(text) >= 2 and text[0] in "'\"" and text[-1] == text[0] and m[0] == text[0]
            and m[-1] == text[0] and all(ch in (STR, "\n", "\r") for ch in m[1:-1]))


ASSIGNABLE_RE = re.compile(r"^\$\w+(?:\[[^\]]*\]|->\w+)*$")
WHILE_RE = re.compile(r"(?<![\w$>:])while\s*\(", re.I)
EACH_CALL_RE = re.compile(r"(?<![\w$>:\\])each\s*\(", re.I)
IMPLODE_RE = re.compile(r"(?<![\w$>:\\])(implode|join)\s*\(", re.I)


def line_of(text, off):
    return text.count("\n", 0, off) + 1


REGEX_META = set(".^$|()[]{}*+?")


def regex_as_literal(pattern):
    """If a POSIX regex matches only a fixed string, return that string."""
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= len(pattern) or pattern[i + 1].isalnum():
                return None
            out.append(pattern[i + 1])
            i += 2
            continue
        if ch in REGEX_META:
            return None
        out.append(ch)
        i += 1
    return "".join(out) or None


def php_quote(s):
    """Shortest correct PHP literal for s."""
    if any(ord(c) < 32 or ord(c) == 127 for c in s):
        out = []
        for c in s:
            if c in '\\"$':
                out.append("\\" + c)
            elif c == "\n":
                out.append("\\n")
            elif c == "\t":
                out.append("\\t")
            elif c == "\r":
                out.append("\\r")
            elif ord(c) < 32 or ord(c) == 127:
                out.append("\\x%02x" % ord(c))
            else:
                out.append(c)
        return '"' + "".join(out) + '"'
    out = []
    for i, c in enumerate(s):
        if c == "'":
            out.append("\\'")
        elif c == "\\" and (i + 1 == len(s) or s[i + 1] in "\\'"):
            out.append("\\\\")
        else:
            out.append(c)
    return "'" + "".join(out) + "'"


def pcre_literal(posix, ci):
    p = []
    for c in posix:
        if c == "\n":
            p.append("\\n")
        elif c == "\t":
            p.append("\\t")
        elif c == "\r":
            p.append("\\r")
        elif ord(c) < 32:
            p.append("\\x%02x" % ord(c))
        elif c == "~":
            p.append("\\~")
        else:
            p.append(c)
    return php_quote("~" + "".join(p) + "~" + ("i" if ci else ""))


# ======================================================================================
# File conversion
# ======================================================================================
class Converter:
    def __init__(self, link, kinds, codebase_funcs):
        self.link = link
        self.kinds = kinds
        self.do_mysql = "mysql" in kinds
        self.do_regex = "regex" in kinds
        self.codebase_funcs = codebase_funcs

    def convert(self, raw):
        self.stats = Counter()
        self.manual = []        # (line, name, reason)
        self.warnings = []      # (line, message)
        self.helper_used = False
        text = raw
        if "tags" in self.kinds:
            text = self.fix_short_tags(text)
        if "each" in self.kinds and "each" not in self.codebase_funcs:
            text = self.fix_each(text)
        if "implode" in self.kinds:
            text = self.fix_implode(text)
        if self.do_mysql or self.do_regex:
            text = self.convert_calls(text)
        return text

    # ---------------- short open tags ----------------
    def fix_short_tags(self, text):
        tags = []
        mask_php(text, tags)
        for j in reversed(tags):
            nxt = text[j + 2:j + 3]
            text = text[:j] + "<?php" + ("" if nxt in ("", " ", "\t", "\n", "\r") else " ") + text[j + 2:]
        if tags:
            self.stats["<? short open tag -> <?php"] += len(tags)
        return text

    # ---------------- while (list() = each()) ----------------
    def fix_each(self, text):
        masked = mask_php(text)
        out, pos = [], 0
        for m in WHILE_RE.finditer(masked):
            if m.start() < pos:
                continue
            open_idx = m.end() - 1
            close = match_parens(masked, open_idx)
            if close < 0:
                continue
            lm = re.match(r"\s*list\s*\(", masked[open_idx + 1:close], re.I)
            if not lm:
                continue
            lopen = open_idx + lm.end()
            lclose = match_parens(masked, lopen)
            if lclose < 0 or lclose >= close:
                continue
            em = re.match(r"\s*=\s*each\s*\(", masked[lclose + 1:close], re.I)
            if not em:
                continue
            eopen = lclose + em.end()
            eclose = match_parens(masked, eopen)
            if eclose < 0 or masked[eclose + 1:close].strip():
                continue
            line = line_of(text, m.start())
            following = masked[close + 1:].lstrip()[:1]
            if following in (";", ":"):
                self.manual.append((line, "each", "do-while or 'while (...):' syntax - convert by hand"))
                continue
            espans = arg_spans(masked, eopen + 1, eclose)
            if len(espans) != 1:
                continue
            expr = text[espans[0][0]:espans[0][1]]
            tk = [text[s:e] for s, e in arg_spans(masked, lopen + 1, lclose)]
            if any(t and not ASSIGNABLE_RE.match(t) for t in tk) or len(tk) > 2:
                self.manual.append((line, "each", "unusual list() targets - convert by hand"))
                continue
            key = tk[0] if tk else ""
            val = tk[1] if len(tk) == 2 else ""
            if key and val:
                new = "foreach (%s as %s => %s)" % (expr, key, val)
            elif val:
                new = "foreach (%s as %s)" % (expr, val)
            elif key:
                new = "foreach (array_keys(%s) as %s)" % (expr, key)
            else:
                continue
            out.append(text[pos:m.start()])
            out.append(new)
            pos = close + 1
            self.stats["while(list()=each()) -> foreach"] += 1
        out.append(text[pos:])
        text = "".join(out)
        masked = mask_php(text)
        reported = {ln for ln, name, _ in self.manual if name == "each"}
        for m in EACH_CALL_RE.finditer(masked):
            if re.search(r"\bfunction\s*&?\s*$", masked[max(0, m.start() - 40):m.start()], re.I):
                continue
            if line_of(text, m.start()) in reported:
                continue
            self.manual.append((line_of(text, m.start()), "each",
                                "each() outside a while(list(...) = each(...)) loop - rewrite with foreach/key()/next()"))
        return text

    # ---------------- implode($array, 'glue') ----------------
    def fix_implode(self, text):
        masked = mask_php(text)
        swaps = 0
        for m in IMPLODE_RE.finditer(masked):
            open_idx = m.end() - 1
            close = match_parens(masked, open_idx)
            if close < 0:
                continue
            spans = arg_spans(masked, open_idx + 1, close)
            if len(spans) != 2:
                continue
            (s1, e1), (s2, e2) = spans
            if is_string_literal(text, masked, s2, e2) and not is_string_literal(text, masked, s1, e1):
                # swapping keeps the length identical, so later offsets stay valid
                text = text[:s1] + text[s2:e2] + text[e1:s2] + text[s1:e1] + text[e2:]
                masked = masked[:s1] + masked[s2:e2] + masked[e1:s2] + masked[s1:e1] + masked[e2:]
                swaps += 1
        if swaps:
            self.stats["implode/join argument order"] += swaps
        return text

    def convert_calls(self, raw):
        self.raw = raw
        self.masked = mask_php(raw)
        self.line_starts = [0] + [m.end() for m in re.finditer(r"\n", raw)]
        self.calls = []
        for m in CALL_RE.finditer(self.masked):
            start = m.start(2)
            name = m.group(2).lower()
            if m.group(1) and start >= 2 and re.match(r"\w", self.masked[start - 2]):
                continue                                     # Foo\mysql_query(): namespaced
            if re.search(r"\bfunction\s*&?\s*$", self.masked[max(0, start - 40):start], re.I):
                continue                                     # a definition, not a call
            if self.masked[max(0, start - 4):start].lower().endswith("new "):
                continue
            if name.startswith("mysql_") and not self.do_mysql or name in REGEX_FUNCS and not self.do_regex:
                continue
            open_idx = m.end() - 1
            close = match_parens(self.masked, open_idx)
            if close < 0:
                continue
            self.calls.append((start, open_idx, close, name))
        self.starts = [c[0] for c in self.calls]
        new = self.rewrite(0, len(raw))
        new = self.rename_constants(new)
        return new

    def lineno(self, off):
        return bisect.bisect_right(self.line_starts, off)

    def rewrite(self, a, b):
        out, pos = [], a
        k = bisect.bisect_left(self.starts, a)
        while k < len(self.calls):
            start, open_idx, close, name = self.calls[k]
            if start >= b:
                break
            if start < pos or close >= b:
                k += 1
                continue
            out.append(self.raw[pos:start])
            out.append(self.convert_call(start, open_idx, close, name))
            pos = close + 1
            k += 1
        out.append(self.raw[pos:b])
        return "".join(out)

    def keep(self, start, open_idx, close):
        """Leave the call as-is, but still convert calls nested in its arguments."""
        return self.raw[start:open_idx + 1] + self.rewrite(open_idx + 1, close) + ")"

    def rename(self, start, open_idx, close, new_name):
        name_end = start
        while name_end < open_idx and (self.raw[name_end].isalnum() or self.raw[name_end] == "_"):
            name_end += 1
        return new_name + self.raw[name_end:open_idx + 1] + self.rewrite(open_idx + 1, close) + ")"

    def convert_call(self, start, open_idx, close, name):
        line = self.lineno(start)
        if name in REGEX_FUNCS and name not in self.codebase_funcs:
            return self.convert_regex(start, open_idx, close, name, line)
        if name in self.codebase_funcs:
            if name in KNOWN_MYSQL or name in REGEX_FUNCS:     # the app's own polyfill of a built-in
                self.warnings.append((line, "%s() is defined in this codebase (polyfill?) - left unchanged" % name))
            return self.keep(start, open_idx, close)          # the app's own mysql_* helper: not ours to touch
        if name not in KNOWN_MYSQL:
            self.manual.append((line, name, "not a mysql extension function I know - check it"))
            return self.keep(start, open_idx, close)
        spans = arg_spans(self.masked, open_idx + 1, close)
        args = [self.rewrite(s, e) for s, e in spans]
        L = self.link

        def done(text):
            self.stats[name] += 1
            return text

        if name in RESULT_RENAME:
            if RESULT_RENAME[name].startswith("mysql_compat_"):
                self.helper_used = True
            return done(self.rename(start, open_idx, close, RESULT_RENAME[name]))
        if name in LINK_ONLY:
            if len(args) == 0:
                return done("%s(%s)" % (LINK_ONLY[name], L))
            if len(args) == 1:
                return done(self.rename(start, open_idx, close, LINK_ONLY[name]))
        elif name in LINK_LAST:
            new, link_ok, extra = LINK_LAST[name]
            tail = [extra] if extra else []
            if len(args) == 1:
                return done("%s(%s)" % (new, ", ".join([L, args[0]] + tail)))
            if len(args) == 2 and link_ok:
                return done("%s(%s)" % (new, ", ".join([args[1], args[0]] + tail)))
        elif name in FIELD_PROPS:
            if len(args) == 2:
                return done("mysqli_fetch_field_direct(%s, %s)->%s" % (args[0], args[1], FIELD_PROPS[name]))
        elif name in CONNECT:
            if len(args) <= 5:
                self.helper_used = True
                a3 = args[:3]
                if len(args) >= 4:
                    self.warnings.append((line, "%s(): new_link argument dropped (mysqli always opens a new link)" % name))
                if len(args) == 5:
                    self.warnings.append((line, "%s(): client flags dropped - set them with mysqli_real_connect() if needed" % name))
                if CONNECT[name]:
                    a3 = a3 + ["null"] * (3 - len(a3)) + ["true"]
                return done("mysql_compat_connect(%s)" % ", ".join(a3))
        elif name in MANUAL_REASON:
            self.manual.append((line, name, MANUAL_REASON[name]))
            return self.keep(start, open_idx, close)
        self.manual.append((line, name, "unexpected number of arguments (%d)" % len(args)))
        return self.keep(start, open_idx, close)

    def convert_regex(self, start, open_idx, close, name, line):
        ci, kind = REGEX_FUNCS[name]
        spans = arg_spans(self.masked, open_idx + 1, close)
        if not spans:
            self.manual.append((line, name, "no arguments"))
            return self.keep(start, open_idx, close)
        pattern = literal_arg(self.raw, self.masked, *spans[0])
        if pattern is None:
            self.manual.append((line, name, "pattern is not a plain string literal - convert by hand"))
            return self.keep(start, open_idx, close)
        if pattern == "":
            self.manual.append((line, name, "empty pattern"))
            return self.keep(start, open_idx, close)
        rest = [self.rewrite(s, e) for s, e in spans[1:]]
        after = self.masked[close + 1:close + 12]
        if kind == "split":
            if len(rest) not in (1, 2):
                self.manual.append((line, name, "unexpected number of arguments"))
                return self.keep(start, open_idx, close)
            lit = regex_as_literal(pattern)
            self.stats[name] += 1
            if lit is not None and not (ci and lit.lower() != lit.upper()):
                return "explode(%s)" % ", ".join([php_quote(lit)] + rest)
            if len(rest) == 2:
                self.warnings.append((line, "preg_split() limit: check the value (0/-1 both mean 'no limit')"))
            return "preg_split(%s)" % ", ".join([pcre_literal(pattern, ci)] + rest)
        if kind == "match":
            if len(rest) not in (1, 2):
                self.manual.append((line, name, "unexpected number of arguments"))
                return self.keep(start, open_idx, close)
            if re.match(r"\s*[!=]==", after):
                self.warnings.append((line, "%s() result compared with ===/!==: preg_match returns 1/0, "
                                            "ereg returned length/false - check the comparison" % name))
            self.stats[name] += 1
            return "preg_match(%s)" % ", ".join([pcre_literal(pattern, ci)] + rest)
        # replace
        if len(rest) != 2:
            self.manual.append((line, name, "unexpected number of arguments"))
            return self.keep(start, open_idx, close)
        repl = literal_arg(self.raw, self.masked, *spans[1])
        if repl is not None and "$" in repl:
            self.manual.append((line, name, "replacement contains '$', which preg_replace treats as a backreference"))
            return self.keep(start, open_idx, close)
        if repl is None:
            self.warnings.append((line, "%s(): replacement is not a literal - if it can contain '$', escape it "
                                        "for preg_replace" % name))
        self.stats[name] += 1
        return "preg_replace(%s)" % ", ".join([pcre_literal(pattern, ci)] + rest)

    def rename_constants(self, text):
        masked = mask_php(text)
        hits = list(CONST_RE.finditer(masked))
        if not hits or not self.do_mysql:
            return text
        for m in reversed(hits):
            text = text[:m.start()] + "MYSQLI_" + m.group(1) + text[m.end():]
        self.stats["MYSQL_* constants"] += len(hits)
        return text


# ======================================================================================
HELPER_TEMPLATE = r"""<?php
/**
 * mysql_compat.php - helpers used by code converted from mysql_* to mysqli_*
 * (generated by php_mysql_convert.py). Works on PHP 5.6 and PHP 7/8.
 *
 * Load it once before any database code, e.g. in your common include:
 *     require_once __DIR__ . '/mysql_compat.php';
 * or for every script via php.ini:
 *     auto_prepend_file = /var/www/mysql_compat.php
 */

if (!function_exists('mysql_compat_connect')) {
    /**
     * Replacement for mysql_connect() / mysql_pconnect().
     *  - accepts "host:port" and "host:/path/to/socket" like mysql_connect() did
     *  - remembers the link as the default connection in $GLOBALS['__LINKVAR__']
     *    (mysql_* functions used "the last opened link")
     *  - keeps mysql-style error handling: functions return false instead of throwing
     *    (mysqli throws by default since PHP 8.1). Remove the mysqli_report() line once
     *    the code catches mysqli_sql_exception.
     */
    function mysql_compat_connect($host = null, $user = null, $password = null, $persistent = false)
    {
        mysqli_report(MYSQLI_REPORT_OFF);
        $port = null;
        $socket = null;
        if ($host === null || $host === '') {
            $host = ini_get('mysqli.default_host');
        }
        if (is_string($host) && substr_count($host, ':') === 1) {
            list($host, $extra) = explode(':', $host, 2);
            if (ctype_digit($extra)) {
                $port = (int) $extra;
            } elseif ($extra !== '') {
                $socket = $extra;
            }
        }
        if ($persistent) {
            $host = 'p:' . $host;
        }
        $link = mysqli_connect($host, $user, $password, '', $port, $socket);
        if ($link) {
            $GLOBALS['__LINKVAR__'] = $link;
        }
        return $link;
    }
}

if (!function_exists('mysql_compat_error')) {
    /**
     * Replacements for mysql_error() / mysql_errno(). Unlike mysqli_error(), they also report
     * the error of a failed connect (e.g. in "mysql_connect(...) or die(mysql_error())").
     */
    function mysql_compat_error($link = null)
    {
        if ($link === null && isset($GLOBALS['__LINKVAR__'])) {
            $link = $GLOBALS['__LINKVAR__'];
        }
        if ($link instanceof mysqli) {
            return mysqli_error($link);
        }
        $error = mysqli_connect_error();
        return $error === null ? '' : $error;
    }

    function mysql_compat_errno($link = null)
    {
        if ($link === null && isset($GLOBALS['__LINKVAR__'])) {
            $link = $GLOBALS['__LINKVAR__'];
        }
        if ($link instanceof mysqli) {
            return mysqli_errno($link);
        }
        return mysqli_connect_errno();
    }
}

if (!function_exists('mysql_compat_result')) {
    /** Replacement for mysql_result($result, $row, $field = 0). */
    function mysql_compat_result($result, $row, $field = 0)
    {
        if (!$result || !mysqli_data_seek($result, $row)) {
            return false;
        }
        $data = mysqli_fetch_array($result, MYSQLI_BOTH);
        if (!is_array($data)) {
            return false;
        }
        if (!array_key_exists($field, $data) && is_string($field) && strpos($field, '.') !== false) {
            $field = substr($field, strrpos($field, '.') + 1);   // "table.column" -> "column"
        }
        return array_key_exists($field, $data) ? $data[$field] : false;
    }
}
"""


def parse_args():
    p = argparse.ArgumentParser(description="Convert mysql_* to mysqli_* and ereg/split to preg_*/explode.")
    p.add_argument("root", help="Project directory")
    p.add_argument("--apply", action="store_true", help="Write the changes (default: dry run)")
    p.add_argument("--patch", default="mysql_convert.patch", help="Diff file to write (default: %(default)s)")
    p.add_argument("--backup-dir", help="Where to copy originals before --apply (default: <root>.bak-<timestamp>)")
    p.add_argument("--exclude", action="append", default=[], help="Directory name to skip (repeatable)")
    p.add_argument("--include-vendor", action="store_true", help="Also convert vendor/ (skipped by default)")
    p.add_argument("--only", help="Comma-separated subset of: mysql,regex,each,implode,tags (default: all)")
    p.add_argument("--link-var", default="mysql_link",
                   help="Global variable holding the default connection (default: %(default)s)")
    p.add_argument("--helper", default="mysql_compat.php",
                   help="Helper file path relative to root, written with --apply (default: %(default)s)")
    p.add_argument("--max-list", type=int, default=40, help="Manual items / warnings to print (0 = all)")
    return p.parse_args()


def main():
    args = parse_args()
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("Not a directory: %s" % root, file=sys.stderr)
        return 2
    if not re.match(r"^[A-Za-z_]\w*$", args.link_var):
        print("--link-var must be a plain variable name", file=sys.stderr)
        return 2
    skip = SKIP_DIRS | set(args.exclude)
    if not args.include_vendor:
        skip.add("vendor")

    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for fn in sorted(filenames):
            if fn.lower().endswith(PHP_EXTS):
                files.append(os.path.join(dirpath, fn))

    texts = {}
    defined = set()
    for path in files:
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "rb") as fh:
                texts[path] = fh.read().decode(ENC)
        except OSError:
            continue
        for m in DEF_RE.finditer(texts[path]):
            defined.add(m.group(1).lower())
    # functions the app defines itself (e.g. polyfills); never treat calls to them as built-ins
    codebase_funcs = {f for f in defined if f.startswith("mysql_") or f in REGEX_FUNCS or f == "each"}

    all_kinds = {"mysql", "regex", "each", "implode", "tags"}
    kinds = set(k.strip() for k in args.only.split(",")) if args.only else all_kinds
    if not kinds <= all_kinds:
        print("--only accepts: %s" % ",".join(sorted(all_kinds)), file=sys.stderr)
        return 2
    link = "$GLOBALS['%s']" % args.link_var
    conv = Converter(link, kinds, codebase_funcs)
    totals, changed, manual, warnings, helper_needed = Counter(), {}, [], [], False
    patch_parts = []

    for path in files:
        if path not in texts:
            continue
        raw = texts[path]
        if not re.search(r"mysql_|split|ereg|MYSQL_|each|implode|join|<\?(?![pP=xX])", raw, re.I):
            continue
        new = conv.convert(raw)
        rel = os.path.relpath(path, root)
        manual += [(rel, ln, n, r) for ln, n, r in conv.manual]
        warnings += [(rel, ln, w) for ln, w in conv.warnings]
        if new != raw:
            changed[path] = new
            totals.update(conv.stats)
            helper_needed |= conv.helper_used
            patch_parts.append("".join(difflib.unified_diff(
                raw.splitlines(True), new.splitlines(True), "a/" + rel.replace(os.sep, "/"),
                "b/" + rel.replace(os.sep, "/"))))

    with open(args.patch, "w", encoding=ENC, newline="") as fh:
        for part in patch_parts:
            fh.write(part if part.endswith("\n") else part + "\n\\ No newline at end of file\n")

    w = sys.stdout.write
    w("%s: %s\n" % ("APPLY" if args.apply else "DRY RUN", root))
    w("Scanned %d PHP files; %d file(s) %s.\n" % (len(texts), len(changed), "changed" if args.apply else "would change"))
    if totals:
        w("\nConversions:\n")
        for name, cnt in totals.most_common():
            w("  %6d  %s\n" % (cnt, name))
    w("\nDiff written to %s - review it before applying.\n" % os.path.abspath(args.patch))
    if totals["while(list()=each()) -> foreach"]:
        w("\nNote on each() -> foreach: each() continued from the array's current position, foreach always\n"
          "starts at the beginning. Same result when the array was just built or reset() first (the usual case);\n"
          "check loops over an array that was already partly walked with next()/each().\n")

    if manual:
        w("\nNEEDS MANUAL WORK (%d) - left unchanged:\n" % len(manual))
        shown = manual if args.max_list == 0 else manual[:args.max_list]
        for rel, ln, name, reason in shown:
            w("  %s:%d  %s()  - %s\n" % (rel, ln, name, reason))
        if len(shown) < len(manual):
            w("  ... %d more (use --max-list 0)\n" % (len(manual) - len(shown)))
    if warnings:
        w("\nCHECK THESE CONVERSIONS (%d):\n" % len(warnings))
        shown = warnings if args.max_list == 0 else warnings[:args.max_list]
        for rel, ln, msg in shown:
            w("  %s:%d  %s\n" % (rel, ln, msg))
        if len(shown) < len(warnings):
            w("  ... %d more (use --max-list 0)\n" % (len(warnings) - len(shown)))

    resource_hits = []
    for path, new in changed.items():
        for i, line in enumerate(new.splitlines(), 1):
            if re.search(r"\bis_resource\s*\(", line):
                resource_hits.append((os.path.relpath(path, root), i, line.strip()[:100]))
    if resource_hits:
        w("\nis_resource() in converted files (%d): mysqli returns objects, so is_resource($result)/\n"
          "is_resource($link) is now always false. Replace with a !== false / instanceof check:\n" % len(resource_hits))
        for rel, ln, txt in resource_hits[:args.max_list or None]:
            w("  %s:%d  %s\n" % (rel, ln, txt))

    helper_path = os.path.join(root, args.helper)
    if not args.apply:
        w("\nNothing written. Re-run with --apply to change the files.\n")
        if helper_needed:
            w("--apply will also create %s (connect/error/result helpers).\n" % helper_path)
        return 0

    backup = args.backup_dir or "%s.bak-%s" % (root.rstrip(os.sep), datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    for path, new in changed.items():
        rel = os.path.relpath(path, root)
        dest = os.path.join(backup, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(path, dest)
        with open(path, "w", encoding=ENC, newline="") as fh:
            fh.write(new)
    w("\nBacked up %d original file(s) to %s\n" % (len(changed), backup))
    if helper_needed:
        if os.path.exists(helper_path):
            w("Helper %s already exists - not overwritten.\n" % helper_path)
        else:
            with open(helper_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(HELPER_TEMPLATE.replace("__LINKVAR__", args.link_var))
            w("Created %s\n" % helper_path)
        w("\nNEXT: load %s before any database code (require_once in your common include,\n"
          "or auto_prepend_file in php.ini), then lint: find . -name '*.php' -exec php -l {} \\; | grep -v 'No syntax'\n"
          % args.helper)
    return 0


if __name__ == "__main__":
    sys.exit(main())
