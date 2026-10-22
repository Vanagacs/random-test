#!/usr/bin/env python3
"""
php_migrate_check.py - find what must change to move a PHP 5.6 codebase to PHP 7.x / 8.x.

Scans PHP source for:
  * MUST FIX     code that stops working (removed functions/extensions, syntax that no
                 longer parses, things that become fatal errors)
  * BEHAVIOR     code that still runs but silently does something different
  * DEPRECATED   code that emits deprecation warnings on the target version
                 (and will break in a later one)
plus an inventory of PHP extensions the code uses (handy for building the Docker image)
and a composer.json check.

It understands PHP syntax well enough to ignore comments, strings and inline HTML,
so a commented-out mysql_query() is not reported.

Stdlib only, Python 3.6+, read-only.

Usage:
  python3 php_migrate_check.py /path/to/app                 # target: latest (8.5)
  python3 php_migrate_check.py /path/to/app --target 7.4    # stepwise migration
  python3 php_migrate_check.py /path/to/app --csv issues.csv
  python3 php_migrate_check.py /path/to/app --json > report.json
  python3 php_migrate_check.py /path/to/app --max-locations 0   # show every hit

Exit code: 0 = no must-fix issues for the target, 1 = must-fix issues found, 2 = usage error.

Static analysis cannot see everything (types at runtime, values passed around); see the
"Check manually" list at the end of the report, and run your test suite on the new version.
"""

import argparse
import bisect
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict, OrderedDict

LATEST = "8.5"
PHP_EXTS = (".php", ".phtml", ".php3", ".php4", ".php5", ".inc", ".module", ".install",
            ".theme", ".ctp")
MAX_FILE_BYTES = 8 * 1024 * 1024
STR = "\x01"          # placeholder for string contents in the masked view

# --------------------------------------------------------------------------------------
# PHP-aware masking: comments and inline HTML -> spaces, string contents -> STR.
# Newlines are preserved, so line numbers and column offsets match the original.
# --------------------------------------------------------------------------------------
HEREDOC_RE = re.compile(r"<<<[ \t]*([\"']?)([A-Za-z_]\w*)\1[ \t]*\r?\n")
OPEN_TAG_RE = re.compile(r"<\?(php\b|=)?", re.IGNORECASE)
PHP_TOKEN_RE = re.compile(r"\?>|#|//|/\*|['\"`]|<<<")
LINE_COMMENT_RE = re.compile(r"[^\n?]*(?:\?(?!>)[^\n?]*)*")
STRING_RES = {q: re.compile(q + r"[^" + q + r"\\]*(?:\\.[^" + q + r"\\]*)*" + q, re.S) for q in "'\"`"}
NON_NL_RE = re.compile(r"[^\n]")


def _fill(seg, ch=" "):
    return NON_NL_RE.sub(ch, seg)


def mask_php(src):
    parts = []
    n = len(src)
    short_tags = []
    i = 0
    in_php = False
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
            if not m.group(1):
                short_tags.append(j)
            parts.append(_fill(src[j:m.end()]))
            i = m.end()
            in_php = True
            continue

        m = PHP_TOKEN_RE.search(src, i)
        if not m:
            parts.append(src[i:])
            break
        parts.append(src[i:m.start()])
        i = m.start()
        tok = m.group()
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
        else:  # quote
            sm = STRING_RES[tok].match(src, i)
            if sm:
                e = sm.end()
                parts.append(tok + _fill(src[i + 1:e - 1], STR) + tok)
            else:
                e = n
                parts.append(tok + _fill(src[i + 1:e], STR))
            i = e
    out = "".join(parts)
    assert len(out) == n, "masking changed length"
    return out, short_tags


# --------------------------------------------------------------------------------------
# Rules
#   ver  = first version where the code BREAKS (kind "break") or changes behavior
#          ("behavior") or is deprecated ("deprecated")
#   dep  = version where it was deprecated before breaking (optional)
#   mode = "code" (match masked code), "raw" (match original line),
#          "instring" (raw match that must start inside a string literal)
#   need = extra regex the masked line must contain (for raw/instring rules)
# --------------------------------------------------------------------------------------
FN = r"(?<![\w$>:\\])(?<!function )(?<!new )"     # a plain function call, not a method/def
MYSQL_FUNCS = r"mysql_(?:affected_rows|client_encoding|close|connect|create_db|createdb|data_seek|db_name|dbname|db_query|drop_db|dropdb|errno|error|escape_string|fetch_array|fetch_assoc|fetch_field|fetch_lengths|fetch_object|fetch_row|field_flags|fieldflags|field_len|fieldlen|field_name|fieldname|field_seek|field_table|fieldtable|field_type|fieldtype|free_result|freeresult|get_client_info|get_host_info|get_proto_info|get_server_info|info|insert_id|list_dbs|listdbs|list_fields|listfields|list_processes|list_tables|listtables|num_fields|numfields|num_rows|numrows|pconnect|ping|query|real_escape_string|result|select_db|selectdb|set_charset|stat|tablename|table_name|thread_id|unbuffered_query)\b"


def call(names):
    return FN + r"(?:" + names + r")\s*\("


RULES = [
    # ---------------- removed extensions / functions ----------------
    dict(id="mysql-ext", ver="7.0", dep="5.5", kind="break",
         title="mysql_* extension removed",
         fix="Rewrite with mysqli_* or PDO (use prepared statements while you are at it).",
         rx=call(MYSQL_FUNCS)),
    dict(id="ereg", ver="7.0", dep="5.3", kind="break",
         title="ereg / split POSIX regex functions removed",
         fix="ereg->preg_match, ereg_replace->preg_replace, split->preg_split/explode (add delimiters to patterns).",
         rx=call(r"ereg|eregi|ereg_replace|eregi_replace|split|spliti|sql_regcase")),
    dict(id="preg-e", ver="7.0", dep="5.5", kind="break",
         title="preg_replace /e modifier removed",
         fix="Use preg_replace_callback().",
         mode="raw", need=r"preg_replace\s*\(",
         rx=r"preg_replace\s*\(\s*(['\"])([^\w\s\\]).*?\2[a-zA-Z]*e[a-zA-Z]*\1"),
    dict(id="script-tag", ver="7.0", kind="break",
         title="<script language=\"php\"> tags removed",
         fix="Use <?php ... ?>.",
         mode="raw", rx=r"<script\s+language\s*=\s*['\"]?php"),
    dict(id="magic-quotes-runtime", ver="7.0", kind="break",
         title="set_magic_quotes_runtime()/magic_quotes_runtime() removed",
         fix="Remove the call.", rx=call(r"set_magic_quotes_runtime|magic_quotes_runtime")),
    dict(id="call-user-method", ver="7.0", kind="break",
         title="call_user_method() removed",
         fix="Use call_user_func([$obj, 'method'], ...).",
         rx=call(r"call_user_method|call_user_method_array")),
    dict(id="new-by-ref", ver="7.0", kind="break",
         title="Assigning new by reference (=& new) is a parse error",
         fix="Drop the &: $x = new Foo();", rx=r"=\s*&\s*new\b"),
    dict(id="raw-post-data", ver="7.0", kind="break",
         title="$HTTP_RAW_POST_DATA removed",
         fix="Use file_get_contents('php://input').", rx=r"\$HTTP_RAW_POST_DATA\b"),
    dict(id="empty-list", ver="7.0", kind="break",
         title="Empty list() is not allowed",
         fix="Remove the list() or give it variables.", rx=r"\blist\s*\(\s*(?:,\s*)*\)"),
    dict(id="removed-ext-74", ver="7.4", kind="break",
         title="wddx / recode / interbase extensions removed",
         fix="Replace with serialize/json, iconv/mbstring, or PDO_Firebird.",
         rx=call(r"wddx_\w+|recode_\w+|recode|ibase_\w+|fbird_\w+")),
    dict(id="mcrypt", ver="7.2", dep="7.1", kind="break",
         title="mcrypt extension removed",
         fix="Use openssl_encrypt()/openssl_decrypt() or sodium_* (check cipher/padding compatibility for existing data!).",
         rx=call(r"mcrypt_\w+|mdecrypt_generic")),
    dict(id="xmlrpc", ver="8.0", kind="break",
         title="xmlrpc extension removed (PECL only)",
         fix="Use a userland library (e.g. phpxmlrpc) or install from PECL.", rx=call(r"xmlrpc_\w+")),
    dict(id="removed-80", ver="8.0", dep="7.x", kind="break",
         title="Function removed in PHP 8.0",
         fix="each()->foreach; create_function()->closure; money_format()->NumberFormatter; "
             "get_magic_quotes_*()->remove; is_real()->is_float; fgetss()->strip_tags(fgets()); "
             "image2wbmp()->imagewbmp; hebrevc/convert_cyr_string->mb_*/iconv; read_exif_data->exif_read_data.",
         rx=call(r"each|create_function|money_format|ezmlm_hash|restore_include_path|get_magic_quotes_gpc|"
                 r"get_magic_quotes_runtime|hebrevc|convert_cyr_string|is_real|fgetss|image2wbmp|png2wbmp|"
                 r"jpeg2wbmp|gmp_random|read_exif_data|ldap_sort|ldap_control_paged_result|"
                 r"ldap_control_paged_result_response|gzgetss")),
    dict(id="mbregex-aliases", ver="8.0", dep="7.3", kind="break",
         title="mbereg*/mbsplit aliases removed",
         fix="Use the mb_ereg* / mb_split names.",
         rx=call(r"mbereg\w*|mberegi\w*|mbsplit|mbregex_encoding")),
    dict(id="autoload-fn", ver="8.0", dep="7.2", kind="break",
         title="__autoload() no longer called",
         fix="Register it with spl_autoload_register() (or use Composer autoload).",
         rx=r"\bfunction\s+__autoload\s*\("),
    dict(id="php-errormsg", ver="8.0", dep="7.2", kind="break",
         title="$php_errormsg removed",
         fix="Use error_get_last().", rx=r"\$php_errormsg\b"),

    # ---------------- syntax that stops parsing ----------------
    dict(id="curly-offset", ver="8.0", dep="7.4", kind="break",
         title="Curly brace string/array offset $s{0} is a parse error",
         fix="Use square brackets: $s[0].", rx=r"(?:\$\w+|->\w+|\])\{(?!\s*\$\w+\s*\})|\$\w+\s+\{(?=\s*[\d'\"$-])"),
    dict(id="real-unset-cast", ver="8.0", dep="7.2", kind="break",
         title="(real) and (unset) casts removed",
         fix="(real)->(float); (unset)$x->null.", rx=r"\(\s*(?:real|unset)\s*\)"),
    dict(id="nested-ternary", ver="8.0", dep="7.4", kind="break",
         title="Unparenthesized nested ternary is a fatal error",
         fix="Add parentheses: a ? b : (c ? d : e).",
         rx=r"\?(?![?:>])[^?:;(),\n]*:(?!:)[^?;(),\n]*\?(?![?:>])[^:;,\n]*:"),
    dict(id="match-fn", ver="8.0", kind="break",
         title="'match' is a reserved keyword",
         fix="Rename the function match() (methods named match are fine).",
         rx=r"\bfunction\s+&?\s*match\s*\(|(?<![\w$>:\\])(?<!function )match\s*\((?![^)]*\)\s*\{)"),

    # ---------------- reserved class names ----------------
    dict(id="reserved-class-70", ver="7.0", kind="break",
         title="Class name is a reserved type name (int/float/bool/string/true/false/null)",
         fix="Rename the class.", flags=re.I,
         rx=r"\b(?:class|interface|trait)\s+(?:int|float|bool|string|true|false|null)\b"),
    dict(id="reserved-class-71", ver="7.1", kind="break",
         title="Class name 'void' or 'iterable' is reserved", fix="Rename the class.", flags=re.I,
         rx=r"\b(?:class|interface|trait)\s+(?:void|iterable)\b"),
    dict(id="reserved-class-72", ver="7.2", kind="break",
         title="Class name 'object' is reserved", fix="Rename the class.", flags=re.I,
         rx=r"\b(?:class|interface|trait)\s+object\b"),
    dict(id="reserved-class-80", ver="8.0", kind="break",
         title="Class name 'mixed' is reserved", fix="Rename the class.", flags=re.I,
         rx=r"\b(?:class|interface|trait)\s+mixed\b"),
    dict(id="reserved-class-81", ver="8.1", kind="break",
         title="Class name 'never' is reserved", fix="Rename the class.", flags=re.I,
         rx=r"\b(?:class|interface|trait)\s+never\b"),

    # ---------------- calls that become errors ----------------
    dict(id="parse-str-1arg", ver="8.0", dep="7.2", kind="break",
         title="parse_str() without result array argument",
         fix="parse_str($str, $result); then use $result.",
         rx=r"(?<![\w$>:])parse_str\s*\(\s*[^,()]*(?:\([^()]*\))?[^,()]*\)"),
    dict(id="implode-order", ver="8.0", dep="7.4", kind="break",
         title="implode()/join() with array first and glue second",
         fix="Swap the arguments: implode(',', $arr).",
         rx=r"(?<![\w$>:])(?:implode|join)\s*\(\s*\$\w+\s*,\s*['\"]"),
    dict(id="assert-string", ver="8.0", dep="7.2", kind="break",
         title="assert() with a string is no longer evaluated",
         fix="Pass an expression: assert($x > 0).", rx=r"(?<![\w$>:])assert\s*\(\s*['\"]"),
    dict(id="define-ci", ver="8.0", dep="7.3", kind="break",
         title="Case-insensitive constants (define(..., true)) no longer supported",
         fix="Drop the third argument and use the exact constant name everywhere.",
         rx=r"(?<![\w$>:])define\s*\(\s*[^,()]+,(?:[^,;()]|\([^()]*\))+,\s*(?:true|TRUE|True|1)\s*\)"),
    dict(id="globals-write", ver="8.1", kind="break",
         title="Writing to $GLOBALS as a whole is an error",
         fix="Write individual keys: $GLOBALS['x'] = ...", rx=r"\$GLOBALS\s*=(?!=)"),
    dict(id="unbundled-84", ver="8.4", kind="break",
         title="imap / oci8 / pspell extensions moved out of core (PECL)",
         fix="Install from PECL in your image, or replace (e.g. imap -> webklex/php-imap).",
         rx=call(r"imap_\w+|oci_\w+|oci\w+|pspell_\w+")),

    # ---------------- silent behavior changes ----------------
    dict(id="uniform-var-syntax", ver="7.0", kind="behavior",
         title="Indirect variable/property/method access evaluated left-to-right",
         fix="Add braces to keep old meaning: ${$foo['bar']}, $obj->{$prop['x']}, Foo::{$m['x']}().",
         rx=r"\$\$\w+\s*\[|->\s*\$\w+\s*\[|(?<!new )(?<![\w\\])[\w\\]+::\s*\$\w+\s*\[[^\]]*\]\s*\("),
    dict(id="concat-precedence", ver="8.0", dep="7.4", kind="behavior",
         title="'.' now binds weaker than '+'/'-' (\"a\" . $x + 1)",
         fix="Add parentheses to make intent explicit.",
         rx=r"(?<![\d.])\.(?![=.\d])[ \t]*[$\w\x01'\"]+(?:\[[^\]\n]*\]|->\w+|::\w+)*[ \t]*(?<![-+])[+\-](?![+\-=>])[ \t]*[$\w(]"),
    dict(id="is-resource", ver="8.0", kind="behavior",
         title="is_resource() returns false for curl/gd/xml/openssl/... handles (now objects)",
         fix="Compare against false instead: if ($ch !== false).",
         rx=r"(?<![\w$>:])is_resource\s*\("),
    dict(id="short-open-tag", ver="7.0", kind="behavior",
         title="Short open tag <? (depends on short_open_tag ini)",
         fix="Use <?php (or <?= for echo). Official Docker images enable it, most php.ini files don't.",
         mode="special"),

    # ---------------- deprecations ----------------
    dict(id="deprecated-81", ver="8.1", kind="deprecated",
         title="Function deprecated in PHP 8.1",
         fix="strftime->IntlDateFormatter/date(); date_sunrise/sunset->date_sun_info; mhash->hash(); "
             "strptime->date_parse_from_format; odbc_result_all->loop.",
         rx=call(r"strftime|gmstrftime|date_sunrise|date_sunset|mhash\w*|strptime|odbc_result_all")),
    dict(id="filter-sanitize-string", ver="8.1", kind="deprecated",
         title="FILTER_SANITIZE_STRING / FILTER_SANITIZE_STRIPPED / FILE_BINARY / FILE_TEXT",
         fix="Use htmlspecialchars() or strip_tags(); drop FILE_BINARY/FILE_TEXT.",
         rx=r"\b(?:FILTER_SANITIZE_STRING|FILTER_SANITIZE_STRIPPED|FILE_BINARY|FILE_TEXT)\b"),
    dict(id="utf8-encode", ver="8.2", kind="deprecated",
         title="utf8_encode()/utf8_decode() deprecated",
         fix="mb_convert_encoding($s, 'UTF-8', 'ISO-8859-1') (and the reverse).",
         rx=call(r"utf8_encode|utf8_decode")),
    dict(id="dollar-brace-interp", ver="8.2", kind="deprecated",
         title="\"${var}\" string interpolation deprecated",
         fix="Use \"{$var}\".", mode="instring", rx=r"(?<!\\)\$\{\s*\w"),
    dict(id="mb-encodings", ver="8.2", kind="deprecated",
         title="mbstring HTML-ENTITIES/QPrint/Base64/Uuencode encodings deprecated",
         fix="Use htmlentities()/quoted_printable_encode()/base64_encode()/convert_uuencode().",
         mode="instring", need=r"\bmb_\w+\s*\(", flags=re.I,
         rx=r"(?<=['\"])(?:HTML-ENTITIES|HTML|Quoted-Printable|QPrint|BASE64|UUENCODE)(?=['\"])"),
    dict(id="self-callable-string", ver="8.2", kind="deprecated",
         title="Callable strings 'self::m' / 'parent::m' / 'static::m' deprecated",
         fix="Use self::class . '::m', [self::class, 'm'] or a first-class callable.",
         mode="instring", rx=r"(?<=['\"])(?:self|parent|static)::\w+(?=['\"])"),
    dict(id="get-class-noarg", ver="8.3", kind="deprecated",
         title="get_class()/get_parent_class() without argument",
         fix="Use static::class / self::class / parent::class.",
         rx=r"(?<![\w$>:])get_(?:parent_)?class\s*\(\s*\)"),
    dict(id="deprecated-83", ver="8.3", kind="deprecated",
         title="assert_options() / MT_RAND_PHP deprecated",
         fix="Use ini settings zend.assertions/assert.exception; drop MT_RAND_PHP.",
         rx=call(r"assert_options") + r"|\bMT_RAND_PHP\b"),
    dict(id="user-error", ver="8.4", kind="deprecated",
         title="trigger_error() with E_USER_ERROR deprecated",
         fix="Throw an exception (or exit()) instead.",
         rx=r"(?<![\w$>:])trigger_error\s*\([^;]*E_USER_ERROR"),
    dict(id="deprecated-84", ver="8.4", kind="deprecated",
         title="Function/constant deprecated in PHP 8.4",
         fix="mysqli_ping/refresh/kill->reconnect logic/SQL KILL; lcg_value->random_int/Random\\Randomizer; "
             "E_STRICT->remove; CURLOPT_BINARYTRANSFER->remove.",
         rx=call(r"mysqli_ping|mysqli_refresh|mysqli_kill|lcg_value") + r"|\b(?:E_STRICT|CURLOPT_BINARYTRANSFER)\b"),
    dict(id="underscore-class", ver="8.4", kind="deprecated",
         title="Class named _ deprecated", fix="Rename the class.",
         rx=r"\b(?:class|interface|trait)\s+_\b"),
    dict(id="backtick", ver="8.5", kind="deprecated",
         title="Backtick operator (shell execution) deprecated",
         fix="Use shell_exec() explicitly (and escapeshellarg() any input).", rx=r"`"),
    dict(id="noncanonical-cast", ver="8.5", kind="deprecated",
         title="(integer)/(boolean)/(double)/(binary) casts deprecated",
         fix="Use (int)/(bool)/(float)/(string).", flags=re.I,
         rx=r"\(\s*(?:integer|boolean|double|binary)\s*\)"),
    dict(id="case-semicolon", ver="8.5", kind="deprecated",
         title="case/default terminated with ';' instead of ':'",
         fix="Use a colon.", rx=r"\bcase\s+[^:;{}?]+;|(?<![\w$>:])default\s*;"),
    dict(id="null-offset", ver="8.5", kind="deprecated",
         title="null used as array offset", fix="Use '' explicitly.", flags=re.I,
         rx=r"\[\s*null\s*\]|array_key_exists\s*\(\s*null\b"),
    dict(id="deprecated-85", ver="8.5", kind="deprecated",
         title="Function/variable deprecated in PHP 8.5",
         fix="curl_close/curl_share_close/finfo_close/imagedestroy/xml_parser_free->just remove (no-ops since 8.0); "
             "mysqli_execute->mysqli_stmt_execute; socket_set_timeout->stream_set_timeout; "
             "$http_response_header->http_get_last_response_headers(); DATE_RFC7231->DATE_RFC1123.",
         rx=call(r"curl_close|curl_share_close|finfo_close|imagedestroy|xml_parser_free|mysqli_execute|"
                 r"socket_set_timeout") + r"|\$http_response_header\b|\bDATE_RFC7231\b|::RFC7231\b"),
    dict(id="pdo-driver-consts", ver="8.5", kind="deprecated",
         title="Driver-specific PDO constants (PDO::MYSQL_ATTR_* etc.) deprecated",
         fix="Use Pdo\\Mysql::ATTR_* (etc.), available from PHP 8.4 - change this once you are on 8.4+.",
         rx=r"\bPDO::(?:MYSQL|PGSQL|SQLITE|DBLIB|FB|ODBC)_\w+"),
]

# Cheap literal pre-check: a rule only runs on files containing one of these (lowercase).
HINTS = {
    "mysql-ext": ("mysql_",), "ereg": ("ereg", "split", "sql_regcase"), "preg-e": ("preg_replace",),
    "script-tag": ("<script",), "magic-quotes-runtime": ("magic_quotes",), "call-user-method": ("call_user_method",),
    "new-by-ref": ("new",), "raw-post-data": ("http_raw_post_data",), "empty-list": ("list",),
    "removed-ext-74": ("wddx_", "recode", "ibase_", "fbird_"), "mcrypt": ("mcrypt", "mdecrypt"),
    "xmlrpc": ("xmlrpc_",),
    "removed-80": ("each", "create_function", "money_format", "ezmlm_hash", "restore_include_path",
                   "magic_quotes", "hebrevc", "convert_cyr_string", "is_real", "fgetss", "wbmp",
                   "gmp_random", "read_exif_data", "ldap_sort", "ldap_control_paged", "gzgetss"),
    "mbregex-aliases": ("mbereg", "mbsplit", "mbregex"), "autoload-fn": ("__autoload",),
    "php-errormsg": ("php_errormsg",), "curly-offset": ("{",), "real-unset-cast": ("real", "unset"),
    "nested-ternary": ("?",), "match-fn": ("match",),
    "reserved-class-70": ("class", "interface", "trait"), "reserved-class-71": ("class", "interface", "trait"),
    "reserved-class-72": ("class", "interface", "trait"), "reserved-class-80": ("class", "interface", "trait"),
    "reserved-class-81": ("class", "interface", "trait"), "underscore-class": ("class", "interface", "trait"),
    "parse-str-1arg": ("parse_str",), "implode-order": ("implode", "join"), "assert-string": ("assert",),
    "define-ci": ("define",), "globals-write": ("$globals",), "unbundled-84": ("imap_", "oci", "pspell_"),
    "uniform-var-syntax": ("$$", "->$", "::$"), "concat-precedence": (".",), "is-resource": ("is_resource",),
    "deprecated-81": ("strftime", "date_sun", "mhash", "strptime", "odbc_result_all"),
    "filter-sanitize-string": ("filter_sanitize_str", "file_binary", "file_text"),
    "utf8-encode": ("utf8_",), "dollar-brace-interp": ("${",), "mb-encodings": ("mb_",),
    "self-callable-string": ("self::", "parent::", "static::"), "get-class-noarg": ("get_",),
    "deprecated-83": ("assert_options", "mt_rand_php"), "user-error": ("e_user_error",),
    "deprecated-84": ("mysqli_ping", "mysqli_refresh", "mysqli_kill", "lcg_value", "e_strict",
                      "curlopt_binarytransfer"),
    "backtick": ("`",), "noncanonical-cast": ("integer", "boolean", "double", "binary"),
    "case-semicolon": ("case", "default"), "null-offset": ("null",),
    "deprecated-85": ("_close", "imagedestroy", "xml_parser_free", "mysqli_execute", "socket_set_timeout",
                      "http_response_header", "rfc7231"),
    "pdo-driver-consts": ("pdo::",),
}
EXT_HINTS = {
    "mysql (REMOVED - use mysqli/pdo_mysql)": ("mysql_",), "mysqli": ("mysqli",), "pdo": ("pdo",),
    "mcrypt (REMOVED - use openssl/sodium)": ("mcrypt_",), "gd": ("image",), "curl": ("curl_",),
    "mbstring": ("mb_",), "intl": ("collator", "numberformatter", "intldate", "normalizer", "transliterator",
                                   "grapheme_", "idn_to_"),
    "iconv": ("iconv",), "openssl": ("openssl_",), "sodium": ("sodium_",),
    "xml/dom/simplexml": ("dom", "simplexml", "xml"), "soap": ("soap",), "zip": ("zip",), "zlib": ("gz",),
    "bcmath": ("bc",), "gmp": ("gmp_",), "ldap": ("ldap_",), "imap (PECL from 8.4)": ("imap_",),
    "oci8 (PECL from 8.4)": ("oci_",), "pgsql": ("pg_",), "sqlsrv": ("sqlsrv_",), "ftp": ("ftp_",),
    "exif": ("exif_",), "fileinfo": ("finfo", "mime_content_type"), "sockets": ("socket_",),
    "memcache(d)": ("memcache",), "redis": ("redis",), "apcu": ("apc",), "xmlrpc (REMOVED in 8.0)": ("xmlrpc_",),
}

for r in RULES:
    r.setdefault("mode", "code")
    r["hints"] = HINTS.get(r["id"])
    r.setdefault("dep", None)
    if r["mode"] != "special":
        r["re"] = re.compile(r["rx"], r.get("flags", 0))
        r["need_re"] = re.compile(r["need"]) if r.get("need") else None

# Structural checks that need more than one line ---------------------------------------
STRUCT_RULES = {
    "php4-ctor": dict(id="php4-ctor", ver="8.0", dep="7.0", kind="break",
                      title="PHP 4 style constructor (method named like the class) is no longer a constructor",
                      fix="Rename the method to __construct() (keep a wrapper if other code calls it by name)."),
    "required-after-optional": dict(id="required-after-optional", ver="8.0", kind="deprecated",
                                    title="Required parameter after optional parameter",
                                    fix="Reorder parameters, or remove the default from the earlier one."),
    "required-after-null-default": dict(id="required-after-null-default", ver="8.3", kind="deprecated",
                                        title="Required parameter after 'Type $x = null'",
                                        fix="Make it ?Type $x (no default) or reorder."),
    "implicit-nullable": dict(id="implicit-nullable", ver="8.4", kind="deprecated",
                              title="Implicitly nullable parameter (Type $x = null)",
                              fix="Write ?Type $x = null."),
    "serializable": dict(id="serializable", ver="8.1", kind="deprecated",
                         title="Serializable interface without __serialize()/__unserialize()",
                         fix="Add __serialize()/__unserialize() methods."),
    "tentative-return": dict(id="tentative-return", ver="8.1", kind="deprecated",
                             title="Method implementing an internal interface without a return type",
                             fix="Add the return type (e.g. offsetGet(mixed $o): mixed) or #[\\ReturnTypeWillChange]."),
    "dynamic-property": dict(id="dynamic-property", ver="8.2", kind="deprecated",
                             title="Assignment to undeclared property (dynamic property)",
                             fix="Declare the property in the class, or add #[\\AllowDynamicProperties]."),
}
for r in STRUCT_RULES.values():
    r.setdefault("dep", None)
    r["mode"] = "struct"

INTERNAL_IFACE_METHODS = {
    "arrayaccess": {"offsetget", "offsetset", "offsetexists", "offsetunset"},
    "iterator": {"current", "key", "next", "rewind", "valid"},
    "iteratoraggregate": {"getiterator"},
    "countable": {"count"},
    "jsonserializable": {"jsonserialize"},
}

EXTENSIONS = OrderedDict([
    ("mysql (REMOVED - use mysqli/pdo_mysql)", r"(?<![\w$>:\\])" + MYSQL_FUNCS + r"\s*\("),
    ("mysqli", r"\bmysqli_\w+\s*\(|\bnew\s+mysqli\b"),
    ("pdo", r"\bnew\s+PDO\b|\bPDO::"),
    ("mcrypt (REMOVED - use openssl/sodium)", r"\bmcrypt_\w+\s*\("),
    ("gd", r"\bimage(?:create\w*|copy\w*|png|jpeg|gif|webp|destroy|sx|sy|ttftext|string|colorallocate\w*)\s*\("),
    ("curl", r"\bcurl_\w+\s*\("),
    ("mbstring", r"\bmb_\w+\s*\("),
    ("intl", r"\b(?:Collator|NumberFormatter|IntlDateFormatter|Normalizer|Transliterator|grapheme_\w+|idn_to_\w+)\b"),
    ("iconv", r"\biconv(?:_\w+)?\s*\("),
    ("openssl", r"\bopenssl_\w+\s*\("),
    ("sodium", r"\bsodium_\w+\s*\("),
    ("xml/dom/simplexml", r"\b(?:DOMDocument|SimpleXMLElement|simplexml_\w+|xml_parser_create\w*|XMLReader|XMLWriter|XSLTProcessor)\b"),
    ("soap", r"\b(?:SoapClient|SoapServer)\b"),
    ("zip", r"\b(?:ZipArchive|zip_open)\b"),
    ("zlib", r"\bgz(?:open|compress|uncompress|encode|decode|deflate|inflate|file)\s*\("),
    ("bcmath", r"\bbc(?:add|sub|mul|div|mod|pow|sqrt|comp|scale)\s*\("),
    ("gmp", r"\bgmp_\w+\s*\("),
    ("ldap", r"\bldap_\w+\s*\("),
    ("imap (PECL from 8.4)", r"\bimap_\w+\s*\("),
    ("oci8 (PECL from 8.4)", r"\boci_\w+\s*\("),
    ("pgsql", r"\bpg_\w+\s*\("),
    ("sqlsrv", r"\bsqlsrv_\w+\s*\("),
    ("ftp", r"\bftp_\w+\s*\("),
    ("exif", r"\bexif_\w+\s*\("),
    ("fileinfo", r"\bfinfo_\w+\s*\(|\bnew\s+finfo\b|\bmime_content_type\s*\("),
    ("sockets", r"\bsocket_\w+\s*\("),
    ("memcache(d)", r"\bnew\s+Memcached?\b"),
    ("redis", r"\bnew\s+Redis\b"),
    ("apcu", r"\bapcu?_\w+\s*\("),
    ("xmlrpc (REMOVED in 8.0)", r"\bxmlrpc_\w+\s*\("),
])
EXT_RES = [(k, re.compile(v), EXT_HINTS.get(k)) for k, v in EXTENSIONS.items()]

MANUAL_CHECKS = [
    ("8.0", "String-to-number comparison changed: 0 == 'abc' is now false. Review loose == comparisons with user input."),
    ("8.0", "Calling non-static methods statically (Foo::bar() on an instance method) is now a fatal Error."),
    ("8.0", "Many internal functions now throw TypeError/ValueError instead of returning null/false with a warning."),
    ("8.0", "The @ operator no longer silences fatal errors; error_reporting defaults to E_ALL."),
    ("8.0", "count()/sizeof() on non-arrays/non-Countable throws TypeError (was a warning since 7.2)."),
    ("8.0", "Named arguments: call_user_func_array() with string-keyed arrays now passes them as named args."),
    ("7.0", "Integer/float handling: shifts by negative numbers, division by zero, and hex strings like '0x1A' are no longer numeric."),
    ("7.1", "Calling a user function with too few arguments throws ArgumentCountError (was a warning)."),
    ("7.1", "Using [] on a string ($s[] = 'x') is a fatal error; $s = ''; $s['k'] = 1 no longer turns it into an array."),
    ("8.1", "Passing null to non-nullable parameters of internal functions (strlen(null), trim(null)...) is deprecated - very common, only visible at runtime."),
    ("8.2", "Dynamic properties: the static check here only covers classes without a parent; check logs on 8.2+ for the rest."),
    ("All", "Third-party libraries in lib/, vendor/ or Composer: each needs a version that supports the target PHP."),
    ("All", "Run the app on the target version with error_reporting=E_ALL and display/log deprecations; that catches what static analysis can't."),
]


# --------------------------------------------------------------------------------------
def vtuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (99,)


def effective_kind(rule, target):
    """Kind of this rule for the chosen target version, or None if not relevant yet."""
    t = vtuple(target)
    if vtuple(rule["ver"]) <= t:
        return rule["kind"]
    dep = rule.get("dep")
    if dep and dep != "7.x" and vtuple(dep) <= t and vtuple(dep) > (5, 6):
        return "deprecated"
    if dep == "7.x" and t >= (7, 2):
        return "deprecated"
    return None


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


def match_brace(text, open_idx):
    depth = 0
    for k in range(open_idx, len(text)):
        ch = text[k]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return k
    return len(text) - 1


def split_top(params):
    parts, depth, cur = [], 0, []
    for ch in params:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


FUNC_RE = re.compile(r"\bfunction\b\s*&?\s*(\w+)?\s*\(")
CLASS_RE = re.compile(r"\b(?:abstract\s+|final\s+)*class\s+(\w+)([^{;]*)\{", re.I)
PARAM_RE = re.compile(r"^(?P<type>[?\\\w]+\s+)?&?\s*(?P<var>\.\.\.\s*)?\$\w+\s*(?P<def>=.*)?$", re.S)
DEF_FN_RE = re.compile(r"\bfunction\s+&?\s*(\w+)\s*\(")


def struct_checks(masked, add):
    """Checks needing multi-line context. add(rule_id, offset)."""
    # function signatures
    for m in FUNC_RE.finditer(masked):
        close = match_parens(masked, m.end() - 1)
        if close < 0:
            continue
        params = split_top(masked[m.end():close])
        seen_optional = None   # None / "plain" / "null"
        for p in params:
            pm = PARAM_RE.match(p)
            if not pm:
                continue
            typ = (pm.group("type") or "").strip()
            default = (pm.group("def") or "")[1:].strip()
            variadic = bool(pm.group("var"))
            off = m.end() + masked[m.end():close].find(p)
            if default:
                is_null = default.lower() == "null"
                if is_null and typ and not typ.startswith("?") and typ.lower() != "mixed":
                    add("implicit-nullable", off)
                kind = "null" if (is_null and typ) else "plain"
                if seen_optional != "plain":
                    seen_optional = kind
            elif not variadic and seen_optional:
                add("required-after-optional" if seen_optional == "plain" else "required-after-null-default", off)

    namespaced = re.search(r"^\s*namespace\s+[\w\\]+\s*[;{]", masked, re.M) is not None

    for cm in CLASS_RE.finditer(masked):
        name, header = cm.group(1), cm.group(2)
        body_start = cm.end() - 1
        body_end = match_brace(masked, body_start)
        body = masked[body_start:body_end]
        methods = {mm.group(1).lower(): body_start + mm.start() for mm in DEF_FN_RE.finditer(body)}

        if not namespaced and "__construct" not in methods and name.lower() in methods:
            add("php4-ctor", methods[name.lower()])

        impl = re.search(r"\bimplements\s+([\w\\\s,]+)", header, re.I)
        ifaces = {i.strip().lstrip("\\").lower() for i in impl.group(1).split(",")} if impl else set()

        if "serializable" in ifaces and "__serialize" not in methods:
            add("serializable", cm.start())

        wanted = set()
        for iface in ifaces:
            wanted |= INTERNAL_IFACE_METHODS.get(iface, set())
        if wanted:
            for mm in DEF_FN_RE.finditer(body):
                if mm.group(1).lower() in wanted:
                    close = match_parens(body, mm.end() - 1)
                    if close > 0 and not re.match(r"\s*:", body[close + 1:close + 40]):
                        add("tentative-return", body_start + mm.start())

        # dynamic properties: only for classes without a parent and without __set
        if re.search(r"\bextends\b", header, re.I) or "__set" in methods:
            continue
        declared = set(re.findall(r"(?:\bvar|\bpublic|\bprotected|\bprivate|\bstatic)\s+(?:static\s+)?"
                                  r"(?:\??[\\\w]+\s+)?\$(\w+)", body))
        declared |= set(re.findall(r",\s*\$(\w+)\s*(?==|;|,)", body))  # var $a, $b;
        reported = set()
        for am in re.finditer(r"\$this->(\w+)\s*(?:\[[^\]]*\]\s*)?(?<![=!<>])=(?![=>])", body):
            prop = am.group(1)
            if prop not in declared and prop not in reported:
                reported.add(prop)
                add("dynamic-property", body_start + am.start())


# --------------------------------------------------------------------------------------
def scan_file(path, rel, rules_active, struct_active, defined_funcs, result):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            result["skipped"].append(rel)
            return
        with open(path, "rb") as f:
            raw = f.read().decode("utf-8", errors="replace")
    except (OSError, IOError):
        result["skipped"].append(rel)
        return

    masked, short_tags = mask_php(raw)
    raw_lines = raw.split("\n")
    m_lines = masked.split("\n")
    line_starts = [0]
    for ln in raw_lines[:-1]:
        line_starts.append(line_starts[-1] + len(ln) + 1)
    result["lines"] += len(raw_lines)

    def lineno(off):
        return bisect.bisect_right(line_starts, off)

    seen = set()

    def record(rule, ln, note=""):
        key = (rule["id"], ln)
        if key in seen:
            return
        seen.add(key)
        text = raw_lines[ln - 1].strip() if 0 < ln <= len(raw_lines) else ""
        result["hits"][rule["id"]].append((rel, ln, text[:200], note))

    polyfill_rules = ("mysql-ext", "removed-80", "mcrypt", "ereg", "removed-ext-74", "xmlrpc", "unbundled-84")
    lower_raw = raw.lower()
    for r in rules_active:
        mode = r["mode"]
        if r.get("hints") and not any(h in lower_raw for h in r["hints"]):
            continue
        if mode == "special":
            if r["id"] == "short-open-tag":
                for off in short_tags:
                    record(r, lineno(off))
            continue
        if mode == "code":
            for mm in r["re"].finditer(masked):
                note = ""
                if r["id"] in polyfill_rules:
                    fn = re.match(r"\s*(\w+)", mm.group(0))
                    if fn and fn.group(1).lower() in defined_funcs:
                        note = "function defined in this codebase (polyfill?)"
                record(r, lineno(mm.start()), note)
            continue
        for mm in r["re"].finditer(raw):
            pos = mm.start()
            ln = lineno(pos)
            mline = m_lines[ln - 1]
            if r["need_re"] and not r["need_re"].search(mline):
                continue
            if mode == "raw":
                if r["id"] != "script-tag" and not mline.strip():
                    continue      # line is entirely comment/HTML
                record(r, ln)
            elif mode == "instring" and masked[pos] == STR:
                record(r, ln)

    if struct_active:
        def add(rule_id, off):
            if rule_id in struct_active:
                record(STRUCT_RULES[rule_id], lineno(off))
        struct_checks(masked, add)

    for name, rx, hints in EXT_RES:
        if hints and not any(h in lower_raw for h in hints):
            continue
        if rx.search(masked):
            result["extensions"][name] += 1


def collect_defined_functions(files):
    names = set()
    for path in files:
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "rb") as f:
                txt = f.read().decode("utf-8", errors="replace")
        except (OSError, IOError):
            continue
        for m in re.finditer(r"^\s*function\s+&?\s*(\w+)\s*\(", txt, re.M):
            names.add(m.group(1).lower())
    return names


def composer_info(root):
    path = os.path.join(root, "composer.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return {"error": str(e)}
    req = data.get("require", {}) or {}
    return {
        "php": req.get("php"),
        "packages": {k: v for k, v in req.items() if k != "php" and not k.startswith("ext-")},
        "dev_packages": data.get("require-dev", {}) or {},
        "extensions": sorted(k for k in req if k.startswith("ext-")),
        "platform": (data.get("config", {}) or {}).get("platform", {}),
        "has_lock": os.path.isfile(os.path.join(root, "composer.lock")),
    }


# --------------------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Find what must change to migrate a PHP 5.6 codebase to PHP 7/8.")
    p.add_argument("root", help="Path to the source tree")
    p.add_argument("--target", default=LATEST, help="Target PHP version (default %s), e.g. 7.4, 8.1, 8.3" % LATEST)
    p.add_argument("--exclude", action="append", default=[], help="Directory name to skip (repeatable)")
    p.add_argument("--include-vendor", action="store_true", help="Also scan vendor/ (skipped by default)")
    p.add_argument("--max-locations", type=int, default=10,
                   help="Locations shown per rule in the text report (0 = all). Default 10")
    p.add_argument("--json", action="store_true", help="Print JSON instead of text")
    p.add_argument("--csv", metavar="FILE", help="Also write every hit to a CSV file (good for a tracking sheet)")
    return p.parse_args()


KIND_ORDER = ["break", "behavior", "deprecated"]
KIND_TITLE = {
    "break": "MUST FIX - code breaks on the target version",
    "behavior": "REVIEW - runs, but behaves differently",
    "deprecated": "DEPRECATED - warnings now, errors in a later version",
}


def main():
    args = parse_args()
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("Not a directory: %s" % root, file=sys.stderr)
        return 2
    if not re.match(r"^\d+\.\d+$", args.target) or vtuple(args.target) < (7, 0):
        print("--target must look like 7.4 or 8.3 (>= 7.0)", file=sys.stderr)
        return 2
    target = args.target

    all_rules = RULES + list(STRUCT_RULES.values())
    kind_of = {r["id"]: effective_kind(r, target) for r in all_rules}
    rules_active = [r for r in RULES if kind_of[r["id"]]]
    struct_active = {k for k, r in STRUCT_RULES.items() if kind_of[k]}
    rule_by_id = {r["id"]: r for r in all_rules}

    skip = set(args.exclude) | {".git", ".svn", ".hg", "node_modules"}
    if not args.include_vendor:
        skip.add("vendor")

    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for fn in sorted(filenames):
            if fn.lower().endswith(PHP_EXTS):
                files.append(os.path.join(dirpath, fn))

    defined_funcs = collect_defined_functions(files)
    result = {"hits": defaultdict(list), "lines": 0, "skipped": [], "extensions": Counter()}
    for path in files:
        scan_file(path, os.path.relpath(path, root), rules_active, struct_active, defined_funcs, result)

    hits = result["hits"]
    groups = {k: [] for k in KIND_ORDER}
    for rid, locs in hits.items():
        groups[kind_of[rid]].append((rid, locs))
    for k in groups:
        groups[k].sort(key=lambda x: (vtuple(rule_by_id[x[0]]["ver"]), -len(x[1])))

    break_by_file = Counter()
    for rid, locs in groups["break"]:
        for loc in locs:
            break_by_file[loc[0]] += 1

    comp = composer_info(root)
    totals = {k: sum(len(l) for _, l in groups[k]) for k in KIND_ORDER}

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["category", "php_version", "rule", "title", "file", "line", "code", "note", "fix"])
            for k in KIND_ORDER:
                for rid, locs in groups[k]:
                    r = rule_by_id[rid]
                    for file_, ln, text, note in locs:
                        w.writerow([k, r["ver"], rid, r["title"], file_, ln, text, note, r["fix"]])

    if args.json:
        out = {
            "root": root, "target": target, "files": len(files), "lines": result["lines"],
            "totals": totals, "skipped": result["skipped"],
            "extensions": dict(result["extensions"]), "composer": comp,
            "issues": [
                {"category": k, "rule": rid, "php_version": rule_by_id[rid]["ver"],
                 "title": rule_by_id[rid]["title"], "fix": rule_by_id[rid]["fix"], "count": len(locs),
                 "locations": [{"file": a, "line": b, "code": c, "note": d} for a, b, c, d in locs]}
                for k in KIND_ORDER for rid, locs in groups[k]
            ],
            "manual_checks": [{"version": v, "check": c} for v, c in MANUAL_CHECKS
                              if v == "All" or vtuple(v) <= vtuple(target)],
        }
        print(json.dumps(out, indent=2))
        return 1 if totals["break"] else 0

    # ---------------------------- text report ----------------------------
    w = sys.stdout.write
    w("PHP migration check: %s\n" % root)
    w("From PHP 5.6 to PHP %s - scanned %d files, %d lines%s\n"
      % (target, len(files), result["lines"],
         "" if args.include_vendor else " (vendor/ skipped)"))
    if result["skipped"]:
        w("Skipped (too large/unreadable): %d files\n" % len(result["skipped"]))
    w("\nSummary: %d must-fix, %d review, %d deprecated\n" % (totals["break"], totals["behavior"], totals["deprecated"]))

    for k in KIND_ORDER:
        if not groups[k]:
            continue
        w("\n" + "=" * 78 + "\n%s  (%d hits)\n" % (KIND_TITLE[k], totals[k]) + "=" * 78 + "\n")
        for rid, locs in groups[k]:
            r = rule_by_id[rid]
            nfiles = len({l[0] for l in locs})
            since = "PHP %s" % r["ver"]
            if k == "deprecated" and r["kind"] != "deprecated":
                since = "deprecated, breaks in PHP %s" % r["ver"]
            w("\n[%s] %s\n" % (since, r["title"]))
            w("    %d hit(s) in %d file(s).  Fix: %s\n" % (len(locs), nfiles, r["fix"]))
            shown = locs if args.max_locations == 0 else locs[:args.max_locations]
            for file_, ln, text, note in shown:
                w("    - %s:%d  %s%s\n" % (file_, ln, text[:120], ("   <- " + note) if note else ""))
            if len(shown) < len(locs):
                w("    ... %d more (use --max-locations 0 or --csv)\n" % (len(locs) - len(shown)))

    if break_by_file:
        w("\n" + "-" * 78 + "\nFiles with the most must-fix hits\n")
        for file_, cnt in break_by_file.most_common(10):
            w("  %5d  %s\n" % (cnt, file_))

    if result["extensions"]:
        w("\n" + "-" * 78 + "\nPHP extensions the code uses (files) - install these in the new image\n")
        for name, cnt in result["extensions"].most_common():
            w("  %5d  %s\n" % (cnt, name))

    w("\n" + "-" * 78 + "\nComposer\n")
    if comp is None:
        w("  No composer.json. Bundled libraries (lib/, includes/...) were scanned as app code;\n"
          "  check if newer versions of them exist rather than patching them by hand.\n")
    elif "error" in comp:
        w("  composer.json could not be read: %s\n" % comp["error"])
    else:
        w("  require php: %s   -> change to e.g. \"^%s\"\n" % (comp["php"] or "(not set)", target))
        if comp["platform"]:
            w("  config.platform overrides: %s  -> update these too\n" % comp["platform"])
        if comp["packages"]:
            w("  %d packages need a version that supports PHP %s (run 'composer why-not php %s'):\n"
              % (len(comp["packages"]), target, target))
            for name, ver in sorted(comp["packages"].items()):
                w("    - %s %s\n" % (name, ver))

    w("\n" + "-" * 78 + "\nCheck manually (not detectable by scanning)\n")
    for v, c in MANUAL_CHECKS:
        if v == "All" or vtuple(v) <= vtuple(target):
            w("  [%s] %s\n" % (v, c))
    w("\nPattern-based scan: expect some false positives and misses. Treat it as a work list,\n"
      "then run the test suite / the app on PHP %s with all deprecations logged.\n" % target)
    if args.csv:
        w("CSV written to %s\n" % args.csv)
    return 1 if totals["break"] else 0


if __name__ == "__main__":
    sys.exit(main())
