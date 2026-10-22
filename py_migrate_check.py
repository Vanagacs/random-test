#!/usr/bin/env python3
"""
py_migrate_check.py - find what must change to move a Python 3.9 codebase to a newer Python
(default target: 3.15, the latest release).

Uses the stdlib `ast` parser, so it understands imports and aliases
(`from collections import Mapping`, `import datetime as dt`) and never matches
comments or strings by accident.

Reports, per target version:
  * MUST FIX     removed modules/functions/arguments, things that now raise errors
  * BEHAVIOR     code that still runs but behaves differently
  * DEPRECATED   warnings on the target version (removal scheduled later)
plus where "3.9" is pinned (Dockerfile, CI, pyproject...), dependency files,
and known-obsolete packages.

Rules are taken from the official "What's New in Python 3.10 ... 3.15" documents.

Stdlib only. Runs on Python 3.9+ (run it with the interpreter you have today).
Read-only.

Usage:
  python3 py_migrate_check.py /path/to/project                # target 3.15
  python3 py_migrate_check.py /path/to/project --target 3.12  # stepwise
  python3 py_migrate_check.py /path/to/project --csv issues.csv
  python3 py_migrate_check.py /path/to/project --json > report.json
  python3 py_migrate_check.py /path/to/project --max-locations 0   # show every hit

Exit code: 0 = no must-fix issues for the target, 1 = must-fix issues found, 2 = usage error.
"""

import argparse
import ast
import csv
import io
import json
import keyword
import os
import re
import sys
import tokenize
import warnings
from collections import Counter, defaultdict

LATEST = "3.15"
FROM = "3.9"
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".tox", ".nox", ".venv", "venv", "env", ".env",
             "site-packages", "node_modules", ".mypy_cache", ".pytest_cache", "build", "dist",
             ".eggs", ".idea", ".vscode"}
MAX_FILE_BYTES = 5 * 1024 * 1024

# =====================================================================================
# Rule catalogue.  ver = version where it breaks / changes / is deprecated (per kind),
# dep = earlier version where it started warning (optional).
# =====================================================================================
RULES = {}


def rule(rid, ver, kind, title, fix, dep=None):
    RULES[rid] = dict(id=rid, ver=ver, kind=kind, title=title, fix=fix, dep=dep)


# ---- removed modules (matched on import) -------------------------------------------
REMOVED_MODULES = {}


def removed_module(mod, ver, fix, dep=None, kind="break"):
    rid = "module:" + mod
    rule(rid, ver, kind, "Module '%s' %s" % (mod, "removed" if kind == "break" else "deprecated"), fix, dep)
    REMOVED_MODULES[mod] = rid


removed_module("parser", "3.10", "Use ast.", dep="3.9")
removed_module("formatter", "3.10", "No replacement; inline the bits you use.", dep="3.4")
removed_module("symbol", "3.10", "Use token / ast.", dep="3.9")
removed_module("binhex", "3.11", "Use base64 / binascii.", dep="3.9")
removed_module("distutils", "3.12", "setup.py: use setuptools; distutils.version: packaging.version; "
                                    "distutils.util.strtobool: write a 5-line helper.", dep="3.10")
removed_module("imp", "3.12", "Use importlib (importlib.util.spec_from_file_location, importlib.reload).", dep="3.4")
for _m in ("asynchat", "asyncore"):
    removed_module(_m, "3.12", "Use asyncio (or pyasyncore from PyPI as a stopgap).", dep="3.6")
removed_module("smtpd", "3.12", "Use aiosmtpd from PyPI.", dep="3.6")
for _m, _fix in [
    ("aifc", "standard-aifc from PyPI"), ("audioop", "audioop-lts from PyPI"), ("chunk", "standard-chunk from PyPI"),
    ("cgi", "urllib.parse.parse_qs/parse_qsl, email.message for headers/multipart (or standard-cgi)"),
    ("cgitb", "traceback / faulthandler (or standard-cgitb)"),
    ("crypt", "hashlib, bcrypt or argon2-cffi"), ("imghdr", "filetype / puremagic / Pillow"),
    ("mailcap", "mimetypes"), ("msilib", "no replacement"), ("nis", "no replacement"),
    ("nntplib", "pynntp from PyPI"), ("ossaudiodev", "no replacement"), ("pipes", "subprocess + shlex.quote"),
    ("sndhdr", "filetype / puremagic"), ("spwd", "python-pam"), ("sunau", "standard-sunau from PyPI"),
    ("telnetlib", "telnetlib3 or Exscript from PyPI"), ("uu", "base64"), ("xdrlib", "standard-xdrlib from PyPI"),
]:
    removed_module(_m, "3.13", "Removed (PEP 594 dead batteries). Use " + _fix + ".", dep="3.11")
removed_module("lib2to3", "3.13", "Use libcst or parso.", dep="3.11")
removed_module("tkinter.tix", "3.13", "Use tkinter.ttk.", dep="3.6")
removed_module("typing.io", "3.13", "Import IO/TextIO/BinaryIO directly from typing.", dep="3.8")
removed_module("typing.re", "3.13", "Use re.Pattern / re.Match.", dep="3.8")
for _m in ("sre_compile", "sre_constants", "sre_parse"):
    removed_module(_m, "3.15", "Private regex internals; use the public re module.", dep="3.11")
removed_module("profile", "3.15", "Use cProfile (or the new profiling package).", kind="deprecated")

# ---- removed / deprecated names (matched on fully resolved names) -------------------
NAME_RULES = {}


def removed_names(rid, names, ver, kind, title, fix, dep=None):
    rule(rid, ver, kind, title, fix, dep)
    for n in names:
        NAME_RULES[n] = rid


ABCS = ["Awaitable", "Coroutine", "AsyncIterable", "AsyncIterator", "AsyncGenerator", "Hashable", "Iterable",
        "Iterator", "Generator", "Reversible", "Sized", "Container", "Callable", "Collection", "Set", "MutableSet",
        "Mapping", "MutableMapping", "MappingView", "KeysView", "ItemsView", "ValuesView", "Sequence",
        "MutableSequence", "ByteString"]
removed_names("collections-abc-alias", ["collections." + a for a in ABCS], "3.10", "break",
              "ABC aliases removed from 'collections' (collections.Mapping etc.)",
              "Import from collections.abc: from collections.abc import Mapping.", dep="3.3")
removed_names("asyncio-coroutine", ["asyncio.coroutine", "asyncio.coroutines.coroutine"], "3.11", "break",
              "@asyncio.coroutine decorator removed",
              "Convert to 'async def' and 'await' instead of 'yield from'.", dep="3.8")
removed_names("inspect-getargspec", ["inspect.getargspec", "inspect.formatargspec"], "3.11", "break",
              "inspect.getargspec()/formatargspec() removed",
              "Use inspect.signature() (or inspect.getfullargspec()).", dep="3.0")
removed_names("gettext-l", ["gettext." + f for f in ("lgettext", "ldgettext", "lngettext", "ldngettext",
                                                       "bind_textdomain_codeset")], "3.11", "break",
              "gettext l*gettext() functions removed", "Use gettext()/ngettext() (they return str).", dep="3.8")
removed_names("binascii-hqx", ["binascii." + f for f in ("a2b_hqx", "b2a_hqx", "rlecode_hqx", "rldecode_hqx")],
              "3.11", "break", "binascii hqx functions removed", "No replacement (binhex format is obsolete).", dep="3.9")
removed_names("removed-312", [
    "configparser.SafeConfigParser", "ssl.wrap_socket", "ssl.match_hostname", "ssl.RAND_pseudo_bytes",
    "locale.format", "io.OpenWrapper", "sqlite3.OptimizedUnicode", "sqlite3.enable_shared_cache",
    "pkgutil.ImpImporter", "pkgutil.ImpLoader", "importlib.abc.Finder", "importlib.util.set_package",
    "importlib.util.set_loader", "importlib.util.module_for_loader", "unittest._TextTestResult"],
    "3.12", "break", "Function/class removed in Python 3.12",
    "SafeConfigParser->ConfigParser; ssl.wrap_socket->ssl.create_default_context().wrap_socket(); "
    "match_hostname->let SSLContext verify (check_hostname=True); RAND_pseudo_bytes->os.urandom; "
    "locale.format->locale.format_string; OpenWrapper->open; pkgutil.Imp*/importlib.util.set_*->importlib APIs.",
    dep="3.7")
removed_names("removed-313", [
    "locale.resetlocale", "unittest.makeSuite", "unittest.findTestCases", "unittest.getTestCaseNames",
    "re.template", "re.TEMPLATE", "re.T", "configparser.LegacyInterpolation"],
    "3.13", "break", "Function/class removed in Python 3.13",
    "resetlocale->locale.setlocale(locale.LC_ALL, ''); makeSuite/findTestCases->"
    "unittest.TestLoader().loadTestsFromTestCase/Module; re.template->re.compile.", dep="3.11")
removed_names("ast-legacy-nodes", ["ast." + n for n in ("Num", "Str", "Bytes", "NameConstant", "Ellipsis")],
              "3.14", "break", "ast.Num/Str/Bytes/NameConstant/Ellipsis removed",
              "Use ast.Constant (and .value instead of .n / .s).", dep="3.8")
removed_names("asyncio-child-watchers", ["asyncio." + n for n in (
    "AbstractChildWatcher", "FastChildWatcher", "MultiLoopChildWatcher", "PidfdChildWatcher", "SafeChildWatcher",
    "ThreadedChildWatcher", "get_child_watcher", "set_child_watcher")], "3.14", "break",
    "asyncio child watcher APIs removed", "Delete them; asyncio handles subprocesses itself.", dep="3.12")
removed_names("removed-314", [
    "importlib.abc.ResourceReader", "importlib.abc.Traversable", "importlib.abc.TraversableResources",
    "pkgutil.get_loader", "pkgutil.find_loader", "pty.master_open", "pty.slave_open", "sqlite3.version",
    "sqlite3.version_info", "urllib.parse.Quoter", "urllib.request.URLopener", "urllib.request.FancyURLopener"],
    "3.14", "break", "Function/class removed in Python 3.14",
    "importlib.abc.*->importlib.resources.abc.*; pkgutil.get/find_loader->importlib.util.find_spec(); "
    "pty.*_open->pty.openpty(); sqlite3.version->sqlite3.sqlite_version; URLopener->urllib.request.urlopen.",
    dep="3.12")
removed_names("removed-315", [
    "ctypes.SetPointerType", "glob.glob0", "glob.glob1", "http.server.CGIHTTPRequestHandler", "platform.java_ver",
    "typing.no_type_check_decorator"], "3.15", "break", "Function/class removed in Python 3.15",
    "glob0/glob1->glob.glob(root_dir=...); CGIHTTPRequestHandler->a real WSGI/ASGI server; "
    "SetPointerType->define the pointer type completely.", dep="3.13")

removed_names("utcnow", ["datetime.datetime.utcnow", "datetime.datetime.utcfromtimestamp"], "3.12", "deprecated",
              "datetime.utcnow()/utcfromtimestamp() deprecated (return naive datetimes)",
              "datetime.now(timezone.utc) / datetime.fromtimestamp(ts, timezone.utc). Note: result becomes "
              "timezone-aware, so comparisons with naive datetimes will raise.")
removed_names("asyncio-policy", ["asyncio." + n for n in (
    "get_event_loop_policy", "set_event_loop_policy", "AbstractEventLoopPolicy", "DefaultEventLoopPolicy",
    "WindowsSelectorEventLoopPolicy", "WindowsProactorEventLoopPolicy")], "3.14", "deprecated",
    "asyncio event loop policy API deprecated (removal in 3.16)",
    "Use asyncio.run(main(), loop_factory=...) or asyncio.Runner(loop_factory=...).")
removed_names("asyncio-iscoroutinefunction", ["asyncio.iscoroutinefunction"], "3.14", "deprecated",
              "asyncio.iscoroutinefunction() deprecated (removal in 3.16)", "Use inspect.iscoroutinefunction().")
removed_names("codecs-open", ["codecs.open"], "3.14", "deprecated", "codecs.open() deprecated",
              "Use open(path, mode, encoding=...).")
removed_names("bytestring", ["typing.ByteString", "collections.abc.ByteString"], "3.12", "deprecated",
              "ByteString deprecated (removal in 3.17)", "Use bytes | bytearray, or collections.abc.Buffer.")
removed_names("ssl-protocols", ["ssl." + n for n in (
    "PROTOCOL_SSLv23", "PROTOCOL_TLS", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1_2",
    "OP_NO_SSLv2", "OP_NO_SSLv3", "OP_NO_TLSv1", "OP_NO_TLSv1_1", "OP_NO_TLSv1_2", "OP_NO_TLSv1_3")],
    "3.10", "deprecated", "Old ssl protocol constants deprecated",
    "Use ssl.PROTOCOL_TLS_CLIENT/SERVER and context.minimum_version = ssl.TLSVersion.TLSv1_2.")
removed_names("logging-warn", ["logging.warn"], "3.10", "deprecated", "logging.warn()/Logger.warn() deprecated",
              "Use .warning().")

# ---- calls with argument checks (handled in code) -----------------------------------
rule("asyncio-loop-param", "3.10", "break", "asyncio 'loop=' argument removed",
     "Drop loop=...; these APIs use the running loop.", dep="3.8")
rule("open-U-mode", "3.11", "break", "open() mode 'U' (universal newlines) removed",
     "Remove the 'U'; text mode already handles all newlines.", dep="3.3")
rule("random-sample-set", "3.11", "break", "random.sample() on a set raises TypeError",
     "random.sample(sorted(s), k) (sorted keeps it reproducible with a seed).", dep="3.9")
rule("random-shuffle-random", "3.11", "break", "random.shuffle() 'random' argument removed",
     "Use a random.Random(seed) instance: rng.shuffle(x).", dep="3.9")
rule("re-global-flag", "3.11", "break", "Inline global regex flag like (?i) not at start of pattern is an error",
     "Move the flag to the very start of the pattern, or pass flags=re.I.", dep="3.6")
rule("unittest-alias", "3.12", "break", "Deprecated unittest assert aliases removed",
     "assertEquals->assertEqual, assertNotEquals->assertNotEqual, assertRegexpMatches->assertRegex, "
     "assertRaisesRegexp->assertRaisesRegex, assert_/failUnless->assertTrue, failIf->assertFalse...", dep="3.2")
rule("configparser-readfp", "3.12", "break", "ConfigParser.readfp() removed", "Use read_file().", dep="3.2")
rule("pkg-resources", "3.12", "break",
     "pkg_resources needs setuptools, which new venvs/Docker images no longer include",
     "Use importlib.metadata (versions/entry points) and importlib.resources (data files); "
     "or add setuptools to requirements as a stopgap.")
rule("urlopen-cafile", "3.13", "break", "urlopen() cafile/capath/cadefault arguments removed",
     "Pass context=ssl.create_default_context(cafile=...).", dep="3.6")
rule("typeddict-kwargs", "3.13", "break", "TypedDict('X', a=int) keyword syntax removed",
     "Use TypedDict('X', {'a': int}) or the class syntax.", dep="3.11")
rule("chained-classmethod", "3.13", "break", "@classmethod stacked on @property no longer works",
     "Use a plain class attribute, a metaclass property, or a small descriptor.", dep="3.11")
rule("pathlib-with", "3.13", "break", "Path objects can no longer be used as context managers ('with Path(...)')",
     "Remove the 'with' (it never did anything).", dep="3.9")
rule("trunc-only", "3.14", "break", "int() no longer falls back to __trunc__()",
     "Define __int__() (or __index__()) on the class.", dep="3.11")
rule("localtime-isdst", "3.14", "break", "email.utils.localtime() isdst argument removed",
     "Drop it; DST is detected automatically.", dep="3.12")
rule("sqlite3-connect-positional", "3.15", "break",
     "sqlite3.connect(): all arguments except the database are keyword-only",
     "sqlite3.connect(db, timeout=5, ...).")
rule("resources-files-package", "3.15", "break", "importlib.resources.files(package=...) keyword removed",
     "Pass it positionally: files('mypkg').", dep="3.12")
rule("namedtuple-kwargs", "3.15", "break", "NamedTuple('P', x=int) keyword syntax removed",
     "Use NamedTuple('P', [('x', int)]) or the class syntax.", dep="3.13")
rule("typeddict-empty", "3.15", "break", "TypedDict('X') / TypedDict('X', None) with no fields removed",
     "Use TypedDict('X', {}) or 'class X(TypedDict): pass'.", dep="3.13")
rule("strptime-day-no-year", "3.15", "break",
     "datetime.strptime() with %d but no year raises ValueError",
     "Add a year to the string and format (e.g. parse '2024-' + s), or parse day/month yourself.", dep="3.13")
rule("co-lnotab", "3.15", "break", "code.co_lnotab removed", "Use code.co_lines().", dep="3.12")
rule("path-is-reserved", "3.15", "break", "PurePath.is_reserved() removed", "Use os.path.isreserved().",
     dep="3.13")
rule("wave-markers", "3.15", "break", "wave getmark()/setmark()/getmarkers() removed", "Remove the calls.",
     dep="3.13")
rule("loader-load-module", "3.15", "break",
     "Import loader defines load_module() only - the import system no longer calls it",
     "Implement create_module()/exec_module() instead.", dep="3.4")

rule("get-event-loop", "3.14", "behavior",
     "asyncio.get_event_loop() raises RuntimeError when no loop is running/set",
     "Use asyncio.run(main()) at the top, asyncio.get_running_loop() inside coroutines.", dep="3.12")
rule("tarfile-filter", "3.14", "behavior",
     "tarfile extraction defaults to the 'data' filter (refuses absolute paths, links outside, device files...)",
     "Pass filter='data' explicitly (or 'tar'/'fully_trusted' if you really need the old behavior).", dep="3.12")
rule("multiprocessing-start", "3.14", "behavior",
     "Default multiprocessing start method on Linux changed from 'fork' to 'forkserver'",
     "Children no longer inherit globals; args must be picklable. Call "
     "multiprocessing.set_start_method('fork') or get_context() explicitly if you rely on fork.")
rule("annotations-access", "3.14", "behavior",
     "Annotations are evaluated lazily (PEP 649); reading __annotations__ directly may behave differently",
     "Use annotationlib.get_annotations() / inspect.get_annotations().")
rule("open-encoding", "3.15", "behavior",
     "open()/read_text()/write_text() without encoding now default to UTF-8, not the locale encoding",
     "Add encoding='utf-8' (or encoding='locale' to keep the old behavior). No change on Linux with a UTF-8 locale.")

rule("finally-flow", "3.14", "deprecated",
     "return/break/continue inside 'finally' (SyntaxWarning, PEP 765)",
     "Move it out of the finally block; it silently swallows exceptions.")
rule("invalid-escape", "3.12", "deprecated",
     "Invalid escape sequence in string ('\\d', '\\.') - SyntaxWarning, will become SyntaxError",
     "Use a raw string r'...' or double the backslash.", dep="3.6")
rule("number-keyword", "3.10", "deprecated", "Numeric literal directly followed by a keyword ('0in x')",
     "Add a space: '0 in x'.")
rule("rmtree-onerror", "3.12", "deprecated", "shutil.rmtree(onerror=...) deprecated",
     "Use onexc= (receives the exception instead of exc_info).")
rule("sslcontext-noarg", "3.10", "deprecated", "ssl.SSLContext() without a protocol deprecated",
     "Use ssl.create_default_context() or SSLContext(ssl.PROTOCOL_TLS_CLIENT).")

ASYNCIO_LOOP_FUNCS = {"asyncio." + f for f in (
    "sleep", "wait_for", "wait", "gather", "shield", "as_completed", "open_connection", "start_server",
    "open_unix_connection", "start_unix_server", "create_subprocess_exec", "create_subprocess_shell",
    "Queue", "LifoQueue", "PriorityQueue", "Lock", "Event", "Condition", "Semaphore", "BoundedSemaphore")}
UNITTEST_ALIASES = {"failUnless", "failIf", "failUnlessEqual", "failIfEqual", "failUnlessAlmostEqual",
                    "failIfAlmostEqual", "failUnlessRaises", "assert_", "assertEquals", "assertNotEquals",
                    "assertAlmostEquals", "assertNotAlmostEquals", "assertRegexpMatches", "assertRaisesRegexp",
                    "assertNotRegexpMatches", "assertDictContainsSubset"}
RE_FUNCS = {"re." + f for f in ("compile", "match", "search", "fullmatch", "sub", "subn", "split", "findall",
                                "finditer")}
INLINE_FLAG_RE = re.compile(r"\(\?[aiLmsux]+\)")
PATH_CLASSES = {"pathlib." + c for c in ("Path", "PurePath", "PosixPath", "WindowsPath")}
MP_NAMES = {"multiprocessing", "concurrent.futures.ProcessPoolExecutor"}

# Packages that do not (or will not) work on new Python versions
OBSOLETE_PACKAGES = {
    "cx_oracle": "cx_Oracle is unmaintained (no wheels for new Python) - switch to 'oracledb' (python-oracledb), "
                 "mostly API-compatible: import oracledb as cx_Oracle.",
    "pycrypto": "pycrypto is dead - use pycryptodome.",
    "nose": "nose does not work on Python 3.10+ - use pytest (runs nose-style tests).",
    "enum34": "Backport that breaks the stdlib enum - remove it.",
    "typing": "The PyPI 'typing' backport breaks modern Python - remove it.",
    "futures": "Python 2 backport - remove it.",
    "asyncio": "The PyPI 'asyncio' package shadows the stdlib - remove it.",
    "dataclasses": "Backport for 3.6 only - remove it.",
    "distribute": "Obsolete setuptools fork - remove it.",
}
OBSOLETE_IMPORTS = {"cx_Oracle": "cx_oracle", "Crypto": None, "nose": "nose"}

MANUAL_CHECKS = [
    ("All", "Every dependency needs a release supporting the target Python (C extensions need new wheels). "
            "Try: uv pip compile requirements.txt --python-version %s  (or pip install in a %s container)."),
    ("All", "Run the test suite on the target with warnings visible: python -W error::DeprecationWarning -m pytest"),
    ("3.11", "asyncio.TimeoutError/socket.timeout are now aliases of TimeoutError; except-clause order may matter."),
    ("3.12", "Mixing tabs and spaces in indentation is now a TabError at tokenize time."),
    ("3.12", "unittest: tests that return a value (not None) emit DeprecationWarning."),
    ("3.13", "locals() in functions returns an independent snapshot each call; code mutating locals() changes."),
    ("3.14", "pickle default protocol is now 5: pickles can't be read by Python < 3.8."),
    ("3.14", "functools.partial is now a method descriptor (stored as a class attribute it binds self)."),
    ("3.14", "NotImplemented in a boolean context raises TypeError."),
    ("3.15", "UTF-8 default (PEP 686) also affects subprocess text mode and reading config/CSV files on Windows."),
]


# =====================================================================================
# Analysis
# =====================================================================================
def vt(v):
    return tuple(int(x) for x in v.split("."))


def effective_kind(r, target):
    t = vt(target)
    if vt(r["ver"]) <= t:
        return r["kind"]
    if r["dep"] and vt(r["dep"]) <= t:
        return "deprecated"
    return None


def const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def get_arg(call, pos, name):
    if len(call.args) > pos and not any(isinstance(a, ast.Starred) for a in call.args[:pos + 1]):
        return call.args[pos]
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def has_kw(call, *names):
    return any(kw.arg in names for kw in call.keywords)


def has_star_kwargs(call):
    return any(kw.arg is None for kw in call.keywords)


class FileScanner(ast.NodeVisitor):
    def __init__(self, tree, source, record):
        self.record = record
        self.source = source
        self.aliases = {}          # local name -> fully qualified name
        self.imported_mods = set()
        self.first_import_line = {}
        self.defined = set()
        self._collect_names(tree)

    # ---------------- import / definition bookkeeping (one pass) ----------------
    def _collect_names(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.defined.add(node.name)
            elif isinstance(node, ast.Assign):
                self.defined.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, ast.Import):
                for a in node.names:
                    self.imported_mods.add(a.name)
                    self.first_import_line.setdefault(a.name.split(".")[0], node.lineno)
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.aliases[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                self.imported_mods.add(node.module)
                self.first_import_line.setdefault(node.module.split(".")[0], node.lineno)
                for a in node.names:
                    if a.name != "*":
                        self.aliases[a.asname or a.name] = node.module + "." + a.name

    def uses(self, mod):
        return any(m == mod or m.startswith(mod + ".") for m in self.imported_mods)

    def qual(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value)
            return base + "." + node.attr if base else None
        return None

    # ---------------- imports ----------------
    def _check_module(self, modname, node):
        for mod, rid in REMOVED_MODULES.items():
            if modname == mod or modname.startswith(mod + "."):
                self.record(rid, node.lineno)
        if modname == "pkg_resources" or modname.startswith("pkg_resources."):
            self.record("pkg-resources", node.lineno)

    def visit_Import(self, node):
        for a in node.names:
            self._check_module(a.name, node)

    def visit_ImportFrom(self, node):
        if node.module and not node.level:
            self._check_module(node.module, node)
            for a in node.names:
                full = node.module + "." + a.name
                self._check_module(full, node)
                if full in NAME_RULES:
                    self.record(NAME_RULES[full], node.lineno)

    # ---------------- names / attributes ----------------
    def visit_Attribute(self, node):
        q = self.qual(node)
        if q and q in NAME_RULES:
            self.record(NAME_RULES[q], node.lineno)
        if node.attr == "co_lnotab":
            self.record("co-lnotab", node.lineno)
        if node.attr == "__annotations__" and isinstance(node.ctx, ast.Load):
            self.record("annotations-access", node.lineno)
        if q and (q.startswith("typing.io.") or q.startswith("typing.re.")):
            self.record(REMOVED_MODULES[".".join(q.split(".")[:2])], node.lineno)
        self.generic_visit(node)

    def visit_Name(self, node):
        q = self.aliases.get(node.id)
        if q and q in NAME_RULES and isinstance(node.ctx, ast.Load):
            self.record(NAME_RULES[q], node.lineno)

    # ---------------- calls ----------------
    def visit_Call(self, node):
        q = self.qual(node.func)
        f = node.func
        attr = f.attr if isinstance(f, ast.Attribute) else None
        line = node.lineno

        if q in ASYNCIO_LOOP_FUNCS and has_kw(node, "loop"):
            self.record("asyncio-loop-param", line)

        is_builtin_open = isinstance(f, ast.Name) and f.id == "open" and "open" not in self.aliases \
            and "open" not in self.defined
        if is_builtin_open or q in ("io.open", "codecs.open"):
            mode = const_str(get_arg(node, 1, "mode"))
            if mode and "U" in mode:
                self.record("open-U-mode", line)
            if is_builtin_open or q == "io.open":
                if (mode is None or "b" not in mode) and not has_kw(node, "encoding") \
                        and len(node.args) < 4 and not has_star_kwargs(node) \
                        and not (mode is None and len(node.args) > 1):
                    self.record("open-encoding", line)

        if attr in ("read_text", "write_text") and self.uses("pathlib") and not has_kw(node, "encoding") \
                and not has_star_kwargs(node) and len(node.args) < (1 if attr == "read_text" else 2):
            self.record("open-encoding", line)

        if q == "random.sample" and node.args:
            a0 = node.args[0]
            if isinstance(a0, (ast.Set, ast.SetComp)) or (
                    isinstance(a0, ast.Call) and isinstance(a0.func, ast.Name) and a0.func.id in ("set", "frozenset")):
                self.record("random-sample-set", line)
        if q == "random.shuffle" and (len(node.args) >= 2 or has_kw(node, "random")):
            self.record("random-shuffle-random", line)

        if q in RE_FUNCS:
            pat = get_arg(node, 0, "pattern")
            s = const_str(pat)
            if s is None and isinstance(pat, ast.Constant) and isinstance(pat.value, bytes):
                s = pat.value.decode("latin-1")
            if s:
                m = INLINE_FLAG_RE.search(s, 1)
                if m:
                    self.record("re-global-flag", line)

        if attr in UNITTEST_ALIASES and isinstance(f.value, ast.Name) and f.value.id in ("self", "cls", "tc", "case"):
            self.record("unittest-alias", line)
        if attr == "readfp" and self.uses("configparser"):
            self.record("configparser-readfp", line)
        if attr == "is_reserved" and self.uses("pathlib"):
            self.record("path-is-reserved", line)
        if attr in ("getmark", "setmark", "getmarkers") and self.uses("wave"):
            self.record("wave-markers", line)
        if attr == "warn" and isinstance(f.value, ast.Name) and "log" in f.value.id.lower():
            self.record("logging-warn", line)

        if q == "urllib.request.urlopen" and has_kw(node, "cafile", "capath", "cadefault"):
            self.record("urlopen-cafile", line)
        if q in ("typing.TypedDict", "typing_extensions.TypedDict"):
            if any(kw.arg not in ("total", "closed", "extra_items") for kw in node.keywords if kw.arg):
                self.record("typeddict-kwargs", line)
            if len(node.args) == 1 and not node.keywords or (
                    len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value is None):
                self.record("typeddict-empty", line)
        if q in ("typing.NamedTuple",) and node.keywords and len(node.args) <= 1:
            self.record("namedtuple-kwargs", line)
        if q == "email.utils.localtime" and (has_kw(node, "isdst") or len(node.args) >= 2):
            self.record("localtime-isdst", line)
        if q == "sqlite3.connect" and len(node.args) > 1:
            self.record("sqlite3-connect-positional", line)
        if q == "importlib.resources.files" and has_kw(node, "package"):
            self.record("resources-files-package", line)
        if q and q.endswith(".strptime") and q in ("datetime.datetime.strptime", "datetime.date.strptime"):
            fmt = const_str(get_arg(node, 1, "format"))
            if fmt and "%d" in fmt and not any(y in fmt for y in ("%Y", "%y", "%G")):
                self.record("strptime-day-no-year", line)
        if q == "shutil.rmtree" and has_kw(node, "onerror"):
            self.record("rmtree-onerror", line)
        if q == "ssl.SSLContext" and not node.args and not has_kw(node, "protocol"):
            self.record("sslcontext-noarg", line)
        if q == "asyncio.get_event_loop":
            self.record("get-event-loop", line)
        if self.uses("tarfile") and attr in ("extractall", "extract") and not has_kw(node, "filter"):
            self.record("tarfile-filter", line)
        if q == "shutil.unpack_archive" and not has_kw(node, "filter"):
            self.record("tarfile-filter", line)

        self.generic_visit(node)

    # ---------------- structure ----------------
    def visit_With(self, node):
        for item in node.items:
            ce = item.context_expr
            if isinstance(ce, ast.Call) and self.qual(ce.func) in PATH_CLASSES:
                self.record("pathlib-with", node.lineno)
        self.generic_visit(node)

    def _check_func(self, node):
        names = []
        for d in node.decorator_list:
            target = d.func if isinstance(d, ast.Call) else d
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, ast.Attribute):
                names.append(target.attr)
            else:
                names.append("")
        if "classmethod" in names:
            ci = names.index("classmethod")
            if any(n in ("property", "cached_property") for n in names[ci + 1:]):
                self.record("chained-classmethod", node.lineno)
        self.generic_visit(node)

    visit_FunctionDef = _check_func
    visit_AsyncFunctionDef = _check_func

    def visit_ClassDef(self, node):
        methods = {n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if "__trunc__" in methods and not ({"__int__", "__index__"} & methods):
            self.record("trunc-only", node.lineno)
        if "load_module" in methods and "exec_module" not in methods and self.uses("importlib"):
            self.record("loader-load-module", node.lineno)
        self.generic_visit(node)

    def visit_Try(self, node):
        for stmt in node.finalbody:
            for ln in _finally_escapes(stmt):
                self.record("finally-flow", ln)
        self.generic_visit(node)

    if sys.version_info >= (3, 11):
        visit_TryStar = visit_Try

    def finish(self, tree):
        if any(self.uses(m) for m in MP_NAMES) or "ProcessPoolExecutor" in self.aliases:
            if not re.search(r"set_start_method|get_context|mp_context", self.source):
                ln = self.first_import_line.get("multiprocessing") or self.first_import_line.get("concurrent") or 1
                self.record("multiprocessing-start", ln)


def _finally_escapes(stmt, in_loop=False):
    """Yield line numbers of return/break/continue that leave a finally block."""
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    if isinstance(stmt, ast.Return):
        yield stmt.lineno
        return
    if isinstance(stmt, (ast.Break, ast.Continue)) and not in_loop:
        yield stmt.lineno
        return
    loop = isinstance(stmt, (ast.For, ast.AsyncFor, ast.While))
    for child in ast.iter_child_nodes(stmt):
        if isinstance(child, ast.stmt):
            # break/continue in a loop's else-clause still leave the finally; keep it simple:
            for ln in _finally_escapes(child, in_loop or loop):
                yield ln


def token_checks(source, record):
    """Numeric literal directly followed by a keyword, e.g. '0in x'."""
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return
    for a, b in zip(toks, toks[1:]):
        if a.type == tokenize.NUMBER and b.type == tokenize.NAME and a.end == b.start \
                and keyword.iskeyword(b.string):
            record("number-keyword", a.start[0])


def parse_with_warnings(source, rel, record):
    """Parse once; the parser itself reports invalid escape sequences as warnings."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        tree = ast.parse(source, filename=rel)
    for w in caught:
        msg = str(w.message)
        if "invalid escape sequence" in msg or "invalid octal escape" in msg:
            record("invalid-escape", w.lineno or 0)
    return tree


# =====================================================================================
# Project files: version pins and dependencies
# =====================================================================================
PIN_FILES_RE = re.compile(r"^(Dockerfile.*|.*\.dockerfile|docker-compose.*\.ya?ml|Jenkinsfile.*|.*\.ya?ml|"
                          r"pyproject\.toml|setup\.cfg|setup\.py|tox\.ini|\.python-version|runtime\.txt|"
                          r"Pipfile|Makefile|.*\.cfg|.*\.ini|.*\.sh)$", re.I)
PIN_RE = re.compile(r"(?i)(python[:\-_ /]?3\.9(?!\d)|py39\b|cp39\b|python_version\s*[<>=!~]=?\s*['\"]?3\.9(?!\d)|"
                    r"requires-python\s*=\s*['\"][^'\"]*3\.9|python_requires\s*=\s*['\"][^'\"]*3\.9|"
                    r"^\s*3\.9(\.\d+)?\s*$)")
REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(.*)$")


def scan_project_files(root, skip):
    pins, deps = [], {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            is_req = re.match(r"(?i)^requirements.*\.(txt|in)$", fn) or fn.lower() in ("pipfile", "pyproject.toml")
            if not (PIN_FILES_RE.match(fn) or is_req):
                continue
            try:
                if os.path.getsize(path) > 1024 * 1024:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if PIN_RE.search(line) and not line.lstrip().startswith("#!"):
                    pins.append((rel, i, line.strip()[:150]))
            if is_req and fn.lower().endswith((".txt", ".in")):
                for line in text.splitlines():
                    line = line.split("#")[0].strip()
                    if not line or line.startswith(("-", "git+", "http")):
                        continue
                    m = REQ_LINE_RE.match(line)
                    if m:
                        deps[m.group(1)] = (m.group(3).strip(), rel)
            elif fn.lower() == "pyproject.toml":
                block = re.search(r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]", text)
                if block:
                    for item in re.findall(r"['\"]([^'\"]+)['\"]", block.group(1)):
                        m = REQ_LINE_RE.match(item)
                        if m:
                            deps[m.group(1)] = (m.group(3).strip(), rel)
                poetry = re.search(r"(?ms)^\[tool\.poetry\.dependencies\](.*?)(^\[|\Z)", text)
                if poetry:
                    for m in re.finditer(r"(?m)^([A-Za-z0-9_.\-]+)\s*=\s*['\"]([^'\"]+)['\"]", poetry.group(1)):
                        if m.group(1).lower() != "python":
                            spec = m.group(2)
                            deps[m.group(1)] = (("==" + spec) if re.match(r"^\d", spec) else spec, rel)
            elif fn.lower() == "pipfile":
                sec = re.search(r"(?ms)^\[packages\](.*?)(^\[|\Z)", text)
                if sec:
                    for m in re.finditer(r"(?m)^([A-Za-z0-9_.\-]+)\s*=\s*(.+)$", sec.group(1)):
                        deps[m.group(1)] = (m.group(2).strip().strip("'\""), rel)
    return pins, deps


# =====================================================================================
def parse_args():
    p = argparse.ArgumentParser(description="Find what must change to move a Python %s project to newer Python."
                                            % FROM)
    p.add_argument("root", help="Project directory")
    p.add_argument("--target", default=LATEST, help="Target Python version (default %s), e.g. 3.12" % LATEST)
    p.add_argument("--exclude", action="append", default=[], help="Directory name to skip (repeatable)")
    p.add_argument("--max-locations", type=int, default=10,
                   help="Locations shown per rule in the text report (0 = all). Default 10")
    p.add_argument("--json", action="store_true", help="Print JSON instead of text")
    p.add_argument("--csv", metavar="FILE", help="Also write every hit to a CSV file")
    return p.parse_args()


KIND_ORDER = ["break", "behavior", "deprecated"]
KIND_TITLE = {
    "break": "MUST FIX - fails on the target version",
    "behavior": "REVIEW - runs, but behaves differently",
    "deprecated": "DEPRECATED - warnings now, errors in a later version",
}


def main():
    args = parse_args()
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("Not a directory: %s" % root, file=sys.stderr)
        return 2
    if not re.match(r"^3\.\d+$", args.target) or vt(args.target) <= vt(FROM):
        print("--target must look like 3.12 and be newer than %s" % FROM, file=sys.stderr)
        return 2
    target = args.target
    kind_of = {rid: effective_kind(r, target) for rid, r in RULES.items()}
    skip = SKIP_DIRS | set(args.exclude)

    hits = defaultdict(list)
    parse_errors = []
    obsolete_imports = defaultdict(set)
    nfiles = nlines = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not d.endswith(".egg-info"))
        for fn in sorted(filenames):
            if not fn.endswith((".py", ".pyw")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                with open(path, "rb") as fh:
                    raw = fh.read()
                enc = tokenize.detect_encoding(io.BytesIO(raw).readline)[0]
                source = raw.decode(enc, errors="replace")
            except (OSError, SyntaxError, LookupError):
                parse_errors.append((rel, 0, "could not read/decode"))
                continue
            nfiles += 1
            lines = source.splitlines()
            nlines += len(lines)
            seen = set()

            def record(rid, ln, _rel=rel, _lines=lines, _seen=seen):
                if not kind_of.get(rid):
                    return
                key = (rid, ln)
                if key in _seen:
                    return
                _seen.add(key)
                text = _lines[ln - 1].strip() if 0 < ln <= len(_lines) else ""
                hits[rid].append((_rel, ln, text[:200]))

            try:
                tree = parse_with_warnings(source, rel, record)
            except (SyntaxError, ValueError) as e:
                parse_errors.append((rel, getattr(e, "lineno", 0) or 0, "%s on Python %d.%d: %s"
                                     % (type(e).__name__, sys.version_info[0], sys.version_info[1],
                                        getattr(e, "msg", e))))
                continue
            scanner = FileScanner(tree, source, record)
            scanner.visit(tree)
            scanner.finish(tree)
            if re.search(r"\d(?:and|or|in|is|if|else|not|for)\b", source):
                token_checks(source, record)
            for name, pkg in OBSOLETE_IMPORTS.items():
                if name in scanner.imported_mods or any(m.startswith(name + ".") for m in scanner.imported_mods):
                    obsolete_imports[pkg or name.lower()].add(rel)

    pins, deps = scan_project_files(root, skip)
    obsolete_deps = {}
    for name, (spec, src) in deps.items():
        key = name.lower().replace("-", "_")
        for bad, msg in OBSOLETE_PACKAGES.items():
            if key == bad.replace("-", "_"):
                obsolete_deps[name] = (spec, src, msg)
    for pkg, files in obsolete_imports.items():
        if pkg == "crypto":
            continue  # Crypto may come from pycryptodome (fine)
        if pkg in OBSOLETE_PACKAGES and not any(n.lower().replace("-", "_") == pkg for n in obsolete_deps):
            obsolete_deps[pkg] = ("(imported in %d file(s))" % len(files), sorted(files)[0], OBSOLETE_PACKAGES[pkg])

    groups = {k: [] for k in KIND_ORDER}
    for rid, locs in hits.items():
        groups[kind_of[rid]].append((rid, locs))
    for k in groups:
        groups[k].sort(key=lambda x: (vt(RULES[x[0]]["ver"]), -len(x[1])))
    totals = {k: sum(len(l) for _, l in groups[k]) for k in KIND_ORDER}
    totals["break"] += len(obsolete_deps)
    break_by_file = Counter(loc[0] for _, locs in groups["break"] for loc in locs)
    pinned = {n: v for n, v in deps.items() if "==" in v[0]}

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["category", "python_version", "rule", "title", "file", "line", "code", "fix"])
            for k in KIND_ORDER:
                for rid, locs in groups[k]:
                    r = RULES[rid]
                    for file_, ln, text in locs:
                        w.writerow([k, r["ver"], rid, r["title"], file_, ln, text, r["fix"]])
            for name, (spec, src, msg) in sorted(obsolete_deps.items()):
                w.writerow(["break", "", "obsolete-package", name + " " + spec, src, "", "", msg])

    if args.json:
        print(json.dumps({
            "root": root, "from": FROM, "target": target, "scanned_with": "%d.%d" % sys.version_info[:2],
            "files": nfiles, "lines": nlines, "totals": totals,
            "issues": [{"category": k, "rule": rid, "python_version": RULES[rid]["ver"], "title": RULES[rid]["title"],
                        "fix": RULES[rid]["fix"], "count": len(locs),
                        "locations": [{"file": a, "line": b, "code": c} for a, b, c in locs]}
                       for k in KIND_ORDER for rid, locs in groups[k]],
            "obsolete_packages": [{"package": n, "spec": s, "source": src, "fix": m}
                                  for n, (s, src, m) in sorted(obsolete_deps.items())],
            "version_pins": [{"file": a, "line": b, "text": c} for a, b, c in pins],
            "dependencies": {n: {"spec": s, "source": src} for n, (s, src) in sorted(deps.items())},
            "parse_errors": [{"file": a, "line": b, "error": c} for a, b, c in parse_errors],
        }, indent=2))
        return 1 if totals["break"] else 0

    w = sys.stdout.write
    w("Python migration check: %s\n" % root)
    w("From Python %s to %s - scanned %d files, %d lines (using Python %d.%d)\n"
      % (FROM, target, nfiles, nlines, sys.version_info[0], sys.version_info[1]))
    w("\nSummary: %d must-fix, %d review, %d deprecated\n" % (totals["break"], totals["behavior"], totals["deprecated"]))

    if parse_errors:
        w("\n!! %d file(s) could not be parsed (Python 2 leftovers? Fix these first):\n" % len(parse_errors))
        for file_, ln, msg in parse_errors[:20]:
            w("    - %s:%d  %s\n" % (file_, ln, msg))

    for k in KIND_ORDER:
        if not groups[k] and not (k == "break" and obsolete_deps):
            continue
        w("\n" + "=" * 78 + "\n%s  (%d hits)\n" % (KIND_TITLE[k], totals[k]) + "=" * 78 + "\n")
        if k == "break" and obsolete_deps:
            w("\n[packages] Obsolete dependencies that won't install or work on new Python\n")
            for name, (spec, src, msg) in sorted(obsolete_deps.items()):
                w("    - %s %s  (%s)\n      %s\n" % (name, spec, src, msg))
        for rid, locs in groups[k]:
            r = RULES[rid]
            since = "Python %s" % r["ver"]
            if k == "deprecated" and r["kind"] != "deprecated":
                since = "deprecated, %s in Python %s" % ("breaks" if r["kind"] == "break" else "changes", r["ver"])
            w("\n[%s] %s\n" % (since, r["title"]))
            w("    %d hit(s) in %d file(s).  Fix: %s\n" % (len(locs), len({l[0] for l in locs}), r["fix"]))
            shown = locs if args.max_locations == 0 else locs[:args.max_locations]
            for file_, ln, text in shown:
                w("    - %s:%d  %s\n" % (file_, ln, text[:120]))
            if len(shown) < len(locs):
                w("    ... %d more (use --max-locations 0 or --csv)\n" % (len(locs) - len(shown)))

    if break_by_file:
        w("\n" + "-" * 78 + "\nFiles with the most must-fix hits\n")
        for file_, cnt in break_by_file.most_common(10):
            w("  %5d  %s\n" % (cnt, file_))

    w("\n" + "-" * 78 + "\nWhere Python %s is pinned (update these to %s)\n" % (FROM, target))
    if pins:
        for file_, ln, text in pins[:40]:
            w("    - %s:%d  %s\n" % (file_, ln, text))
    else:
        w("    Nothing found in Dockerfiles/CI/pyproject/setup files.\n")

    w("\n" + "-" * 78 + "\nDependencies\n")
    if deps:
        w("    %d declared, %d pinned with '=='. Pinned versions are the usual blockers - old pins often\n"
          "    have no wheels for Python %s. Check with:\n"
          "      uv pip compile requirements.txt --python-version %s\n" % (len(deps), len(pinned), target, target))
        for name, (spec, src) in sorted(pinned.items())[:60]:
            w("    - %s%s\n" % (name, spec))
    else:
        w("    No requirements*.txt / pyproject.toml / Pipfile found.\n")

    w("\n" + "-" * 78 + "\nCheck manually (not detectable by scanning)\n")
    for v, c in MANUAL_CHECKS:
        if v == "All" or vt(v) <= vt(target):
            w("  [%s] %s\n" % (v, c.replace("%s", target) if "%s" in c else c))
    w("\nStatic scan: expect a few false positives and some misses. Treat it as a work list, then run\n"
      "your tests on Python %s.\n" % target)
    if args.csv:
        w("CSV written to %s\n" % args.csv)
    return 1 if totals["break"] else 0


if __name__ == "__main__":
    sys.exit(main())
