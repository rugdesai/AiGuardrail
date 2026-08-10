import os
import re
import json
import uuid
import asyncio
import shutil
import tempfile
import subprocess
import hashlib
import time
import sys
from typing import Optional, List, Dict, Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel, Field
import tree_sitter_c as tsc
from tree_sitter import Language, Parser

load_dotenv()

GPU_TUNNEL_URL = os.getenv("GPU_TUNNEL_URL", "http://localhost:11434").rstrip("/")
IBM_URL = os.getenv(
    "IBM_URL",
    "https://eu-de.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29",
)
IBM_MODEL_ID = os.getenv("IBM_MODEL_ID", "meta-llama/llama-3-3-70b-instruct")
LLAMA_MODEL = os.getenv("LLAMA_MODEL", "llama3.3:70b")
SEMGREP_CONFIG = os.getenv("SEMGREP_CONFIG", "p/security-audit")
SANDBOX_URL = os.getenv("SANDBOX_URL", "")

# --- Latency knobs -----------------------------------------------------
# IBM is free hackathon credit -> try it first, but do NOT let it eat your
# whole budget. If it hasn't responded in IBM_TIMEOUT seconds, bail to the
# local GPU model instead of waiting.
IBM_TIMEOUT = float(os.getenv("IBM_TIMEOUT", "10"))
LLAMA_TIMEOUT = float(os.getenv("LLAMA_TIMEOUT", "60"))
SANDBOX_TIMEOUT = float(os.getenv("SANDBOX_TIMEOUT", "8"))

# Token/latency budget for the /analyze CORRELATION call only. That call
# just needs to label + explain findings that static tools already found,
# so it stays small and fast. It no longer asks for fixed_code (see
# build_security_prompt) so this budget doesn't need to cover full source.
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "450"))

# Token/latency budget for the /fix generation call, which is a completely
# different job: it has to hand back a COMPLETE corrected source file.
# A flat cap either wastes latency on tiny fixes or truncates big ones
# (a truncated JSON completion looks exactly like a "placeholder" fix to
# a naive check, so this was a real, silent contributor to the bug).
# Scale the budget to the actual size of the input code instead.
FIX_MAX_TOKENS_BASE = int(os.getenv("FIX_MAX_TOKENS_BASE", "700"))
FIX_MAX_TOKENS_CAP = int(os.getenv("FIX_MAX_TOKENS_CAP", "2000"))
FIX_NUM_CTX = int(os.getenv("FIX_NUM_CTX", "8192"))
FIX_TIMEOUT = float(os.getenv("FIX_TIMEOUT", "90"))

# Only pay the LLM tax when deterministic evidence (AST/semgrep/secrets)
# actually found something, or scope drift is heuristically suspected.
STATIC_FINDINGS_THRESHOLD = int(os.getenv("STATIC_FINDINGS_THRESHOLD", "1"))

app = FastAPI(title="VibeGuard Security Orchestrator", version="2.4")

C_LANGUAGE = Language(tsc.language(), "c")
parser = Parser()
parser.set_language(C_LANGUAGE)

# In-memory verdict cache: identical/near-identical snippets skip the LLM
# entirely on repeat calls (great for demo re-runs / judges retesting).
_LLM_CACHE: Dict[str, Dict[str, Any]] = {}
_LLM_CACHE_MAX = 500

# In-memory package-existence cache so repeated deps don't re-hit the registry.
_PKG_EXIST_CACHE: Dict[str, bool] = {}


def estimate_fix_token_budget(code: str) -> int:
    """Fix generation has to hand back the WHOLE corrected file, not just a
    diagnosis, so its output budget needs to scale with input size instead
    of using the same flat cap as the (much smaller) correlation call."""
    approx_input_tokens = max(1, len(code) // 4)
    return min(FIX_MAX_TOKENS_CAP, max(FIX_MAX_TOKENS_BASE, approx_input_tokens * 2))


class CodePayload(BaseModel):
    language: str
    codeSnippet: str
    userPrompt: Optional[str] = None
    fileName: Optional[str] = None


class FixPayload(BaseModel):
    language: str
    codeSnippet: str
    finding: Dict[str, Any]
    userPrompt: Optional[str] = None
    fileName: Optional[str] = None


class DiagnosticItem(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    type: str = "INFO"
    message: str
    lineStart: int = 1
    lineEnd: int = 1

    severity: Optional[str] = None
    confidence: float = 1.0

    cwe: Optional[str] = "CWE-Other"
    owasp: Optional[str] = None

    source: List[str] = Field(default_factory=list)
    evidence: Optional[str] = None
    attackPath: List[str] = Field(default_factory=list)

    remediation: Optional[str] = None
    fixedCode: Optional[str] = None


C_RULES = {
    "gets": {
        "cwe": "CWE-242",
        "owasp": "A05:2025-Injection",
        "severity": "CRITICAL",
        "message": "Use of gets() can cause an unbounded buffer overflow.",
        "remediation": "Replace gets() with a bounded input API such as fgets() and validate the resulting length.",
    },
    "strcpy": {
        "cwe": "CWE-120",
        "owasp": "A05:2025-Injection",
        "severity": "HIGH",
        "message": "strcpy() performs an unbounded string copy and may overflow the destination buffer.",
        "remediation": "Use a correctly sized bounded copy and explicitly validate destination capacity.",
    },
    "strcat": {
        "cwe": "CWE-120",
        "owasp": "A05:2025-Injection",
        "severity": "HIGH",
        "message": "strcat() performs an unbounded append and may overflow the destination buffer.",
        "remediation": "Use a bounded concatenation strategy and verify the remaining destination capacity.",
    },
    "sprintf": {
        "cwe": "CWE-134",
        "owasp": "A05:2025-Injection",
        "severity": "HIGH",
        "message": "sprintf() does not enforce a destination buffer size and can cause memory corruption.",
        "remediation": "Use snprintf() with the actual destination capacity and check its return value.",
    },
    "system": {
        "cwe": "CWE-78",
        "owasp": "A05:2025-Injection",
        "severity": "CRITICAL",
        "message": "system() executes a shell command and can become an OS command injection sink.",
        "remediation": "Avoid shell execution where possible. Prefer an API that passes arguments without a shell and strictly validate untrusted input.",
    },
    "popen": {
        "cwe": "CWE-78",
        "owasp": "A05:2025-Injection",
        "severity": "CRITICAL",
        "message": "popen() invokes a command interpreter and can become an OS command injection sink.",
        "remediation": "Avoid constructing shell commands from untrusted input; use direct process APIs with fixed arguments.",
    },
}

OWASP_BY_CWE = {
    "CWE-22": "A01:2025-Broken Access Control",
    "CWE-78": "A05:2025-Injection",
    "CWE-79": "A05:2025-Injection",
    "CWE-89": "A05:2025-Injection",
    "CWE-95": "A05:2025-Injection",
    "CWE-327": "A04:2025-Cryptographic Failures",
    "CWE-328": "A04:2025-Cryptographic Failures",
    "CWE-345": "A08:2025-Security Misconfiguration",
    "CWE-347": "A08:2025-Security Misconfiguration",
    "CWE-120": "A05:2025-Injection",
    "CWE-134": "A05:2025-Injection",
    "CWE-242": "A05:2025-Injection",
    "CWE-400": "A10:2025-Mishandling of Exceptional Conditions",
    "CWE-502": "A08:2025-Software or Data Integrity Failures",
    "CWE-710": "A06:2025-Insecure Design",
    "CWE-798": "A07:2025-Authentication Failures",
    "CWE-829": "A08:2025-Software or Data Integrity Failures",
    "CWE-841": "A06:2025-Insecure Design",
    "CWE-918": "A01:2025-Broken Access Control",
    "CWE-1395": "A03:2025-Software Supply Chain Failures",
}

SEVERITY_SCORE = {
    "CRITICAL": 10.0,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "INFO": 0.0,
}


def normalize_severity(value: Any) -> str:
    value = str(value or "MEDIUM").upper().strip()
    return value if value in SEVERITY_SCORE else "MEDIUM"


def clamp_confidence(value: Any) -> float:
    try:
        value = float(value)
        if value > 1:
            value /= 100.0
        return max(0.0, min(1.0, value))
    except (TypeError, ValueError):
        return 0.5


# ---------------------------------------------------------------------------
# Deterministic C AST analysis  (unchanged)
# ---------------------------------------------------------------------------

def walk_tree(node):
    yield node
    for child in node.children:
        yield from walk_tree(child)


def node_line(node) -> int:
    return node.start_point[0] + 1


def node_end_line(node) -> int:
    return node.end_point[0] + 1


def run_c_ast_checks(code: str) -> List[DiagnosticItem]:
    diagnostics: List[DiagnosticItem] = []
    tree = parser.parse(code.encode("utf-8", errors="replace"))

    for node in walk_tree(tree.root_node):
        if node.type == "type_definition":
            text = node.text.decode("utf-8", errors="replace")
            if "*" in text and "struct" in text:
                diagnostics.append(
                    DiagnosticItem(
                        type="HIGH",
                        severity="HIGH",
                        confidence=0.88,
                        message=(
                            "Pointer indirection is hidden inside a typedef. "
                            "This can reduce clarity around ownership and memory handling."
                        ),
                        lineStart=node_line(node),
                        lineEnd=node_end_line(node),
                        cwe="CWE-710",
                        owasp="A06:2025-Insecure Design",
                        source=["AST"],
                        evidence=text[:300],
                        remediation=(
                            "Prefer explicit pointer declarations for security-sensitive "
                            "memory ownership and lifetime boundaries."
                        ),
                    )
                )

        if node.type != "call_expression":
            continue

        function_node = None
        for child in node.children:
            if child.type == "identifier":
                function_node = child
                break

        if function_node is None:
            continue

        func = function_node.text.decode("utf-8", errors="replace")
        rule = C_RULES.get(func)
        if not rule:
            continue

        fixed = None
        if func == "gets":
            fixed = "fgets(buffer, sizeof(buffer), stdin);"
        elif func == "sprintf":
            fixed = "snprintf(buffer, sizeof(buffer), ...);"
        elif func == "strcpy":
            fixed = "Use a bounded copy after validating destination capacity."
        elif func == "strcat":
            fixed = "Use a bounded concatenation after validating remaining capacity."
        elif func in {"system", "popen"}:
            fixed = "Replace shell construction with a direct process/API call using validated arguments."

        diagnostics.append(
            DiagnosticItem(
                type=rule["severity"],
                severity=rule["severity"],
                confidence=0.98,
                message=rule["message"],
                lineStart=node_line(node),
                lineEnd=node_end_line(node),
                cwe=rule["cwe"],
                owasp=rule["owasp"],
                source=["AST"],
                evidence=f"AST identified call to {func}().",
                attackPath=[f"call to {func}()", "potential unsafe sink"],
                remediation=rule["remediation"],
                fixedCode=fixed,
            )
        )

    for line_no, line in enumerate(code.splitlines(), start=1):
        if re.search(r'\bprintf\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:\)|,)', line):
            diagnostics.append(
                DiagnosticItem(
                    type="HIGH",
                    severity="HIGH",
                    confidence=0.90,
                    message="Potential uncontrolled format string passed to printf().",
                    lineStart=line_no,
                    lineEnd=line_no,
                    cwe="CWE-134",
                    owasp="A05:2025-Injection",
                    source=["AST", "Pattern"],
                    evidence=line.strip(),
                    remediation="Use printf(\"%s\", value) or another explicit format string.",
                    fixedCode='printf("%s", value);',
                )
            )

    return diagnostics


# Additional high-signal security patterns.
# These are intentionally narrow to reduce false positives.
PY_JS_SECURITY_PATTERNS = [
    (
        re.compile(r'\b(?:jwt\.)?decode\s*\([^)]*verify_signature\s*["\']?\s*:\s*False', re.I),
        "CWE-347", "CRITICAL",
        "JWT signature verification is disabled, allowing token tampering."
    ),
    (
        re.compile(r'\bhashlib\.md5\s*\(', re.I),
        "CWE-328", "HIGH",
        "MD5 is cryptographically broken and should not be used for security-sensitive hashing."
    ),
    (
        re.compile(r'\bhashlib\.sha1\s*\(', re.I),
        "CWE-327", "HIGH",
        "SHA-1 is cryptographically weak and should not be used for security-sensitive hashing."
    ),
]

PY_JS_DANGEROUS_PATTERNS = [
    (re.compile(r"\bos\.system\s*\("), "CWE-78", "CRITICAL",
     "os.system() executes a shell command and is a command injection sink if the argument includes untrusted input."),
    (re.compile(r"\bsubprocess\.(run|call|Popen|check_output|check_call)\([^)]*shell\s*=\s*True"), "CWE-78", "CRITICAL",
     "subprocess call with shell=True can allow command injection if arguments include untrusted input."),
    (re.compile(r"\bos\.popen\s*\("), "CWE-78", "CRITICAL",
     "os.popen() invokes a shell and is a command injection sink if the argument includes untrusted input."),
    (re.compile(r"\beval\s*\("), "CWE-95", "CRITICAL",
     "eval() executes arbitrary code and is dangerous if given any untrusted input."),
    (re.compile(r"\bexec\s*\("), "CWE-95", "HIGH",
     "exec() executes arbitrary code and is dangerous if given any untrusted input."),
    (re.compile(r"\bpickle\.loads?\s*\("), "CWE-502", "HIGH",
     "pickle deserialization of untrusted data can lead to arbitrary code execution."),
    (re.compile(r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"), "CWE-502", "HIGH",
     "yaml.load() without SafeLoader can execute arbitrary code from untrusted YAML."),
    (re.compile(r"child_process\.exec\s*\("), "CWE-78", "CRITICAL",
     "child_process.exec() invokes a shell and is a command injection sink if given untrusted input."),
    (re.compile(r"new\s+Function\s*\("), "CWE-95", "HIGH",
     "new Function() compiles and executes arbitrary code, similar to eval()."),
    (re.compile(r"\.innerHTML\s*="), "CWE-79", "MEDIUM",
     "Assigning to innerHTML with unsanitized input can lead to cross-site scripting (XSS)."),
    (re.compile(r"execute\s*\(\s*[\"'].*%s.*[\"']\s*%"), "CWE-89", "HIGH",
     "String-formatted SQL passed to execute() is vulnerable to SQL injection; use parameterized queries."),
    (re.compile(r"execute\s*\(\s*f[\"']"), "CWE-89", "HIGH",
     "f-string interpolated directly into a SQL execute() call is vulnerable to SQL injection; use parameterized queries."),
]


def run_pattern_checks(code: str, language: str) -> List[DiagnosticItem]:
    """Fast line-based checks for high-signal security patterns."""
    if language.lower() not in {"python", "javascript", "typescript"}:
        return []

    diagnostics = []
    all_patterns = PY_JS_DANGEROUS_PATTERNS + PY_JS_SECURITY_PATTERNS

    for line_no, line in enumerate(code.splitlines(), start=1):
        for pattern, cwe, severity, message in all_patterns:
            if pattern.search(line):
                diagnostics.append(
                    DiagnosticItem(
                        type=severity,
                        severity=severity,
                        confidence=0.90 if cwe in {"CWE-347", "CWE-328", "CWE-327"} else 0.85,
                        message=message,
                        lineStart=line_no,
                        lineEnd=line_no,
                        cwe=cwe,
                        owasp=OWASP_BY_CWE.get(cwe),
                        source=["Pattern"],
                        evidence=line.strip(),
                        attackPath=["security-sensitive operation", message.split(" ")[0]],
                        remediation=(
                            "Use a secure, context-appropriate alternative and validate "
                            "security-sensitive inputs."
                        ),
                    )
                )
    return diagnostics


# ---------------------------------------------------------------------------
# Lightweight source -> sink taint analysis (unchanged)
# ---------------------------------------------------------------------------

TAINT_SOURCES = {
    "python": [
        re.compile(r'\brequest\.(?:args|form|values|json|data)\s*(?:\[[^\]]+\]|\([^)]+\))'),
        re.compile(r'\binput\s*\('),
        re.compile(r'\bos\.environ(?:\.get)?\s*\('),
        re.compile(r'\bflask\.request\.(?:args|form|json|data)'),
    ],
    "javascript": [
        re.compile(r'\breq\.(?:query|body|params)\b'),
        re.compile(r'\bprocess\.env\b'),
        re.compile(r'\b(?:window|document)\.location(?:\.search|\.hash)?\b'),
    ],
    "typescript": [
        re.compile(r'\breq\.(?:query|body|params)\b'),
        re.compile(r'\bprocess\.env\b'),
        re.compile(r'\b(?:window|document)\.location(?:\.search|\.hash)?\b'),
    ],
}

TAINT_SINKS = {
    "python": [
        (re.compile(r'\bos\.system\s*\((.*?)\)'), "os.system()", "CWE-78", "CRITICAL"),
        (re.compile(r'\bos\.popen\s*\((.*?)\)'), "os.popen()", "CWE-78", "CRITICAL"),
        (re.compile(r'\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\((.*?)\)'), "subprocess", "CWE-78", "CRITICAL"),
        (re.compile(r'\beval\s*\((.*?)\)'), "eval()", "CWE-95", "CRITICAL"),
        (re.compile(r'\bexec\s*\((.*?)\)'), "exec()", "CWE-95", "HIGH"),
        (re.compile(r'\bpickle\.loads?\s*\((.*?)\)'), "pickle.loads()", "CWE-502", "HIGH"),
    ],
    "javascript": [
        (re.compile(r'\bchild_process\.exec\s*\((.*?)\)'), "child_process.exec()", "CWE-78", "CRITICAL"),
        (re.compile(r'\beval\s*\((.*?)\)'), "eval()", "CWE-95", "CRITICAL"),
        (re.compile(r'\bnew\s+Function\s*\((.*?)\)'), "new Function()", "CWE-95", "HIGH"),
        (re.compile(r'\.innerHTML\s*=\s*(.*)'), "innerHTML", "CWE-79", "MEDIUM"),
    ],
    "typescript": [
        (re.compile(r'\bchild_process\.exec\s*\((.*?)\)'), "child_process.exec()", "CWE-78", "CRITICAL"),
        (re.compile(r'\beval\s*\((.*?)\)'), "eval()", "CWE-95", "CRITICAL"),
        (re.compile(r'\bnew\s+Function\s*\((.*?)\)'), "new Function()", "CWE-95", "HIGH"),
        (re.compile(r'\.innerHTML\s*=\s*(.*)'), "innerHTML", "CWE-79", "MEDIUM"),
    ],
}


def run_taint_checks(code: str, language: str) -> List[DiagnosticItem]:
    language = language.lower()
    if language not in TAINT_SOURCES:
        return []

    lines = code.splitlines()
    tainted: Dict[str, Dict[str, Any]] = {}
    findings: List[DiagnosticItem] = []

    assignment_re = re.compile(
        r'^\s*(?:const|let|var|[A-Za-z_][A-Za-z0-9_<>\[\]]*\s+)?'
        r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$'
    )

    def source_match(rhs: str):
        for source_re in TAINT_SOURCES[language]:
            m = source_re.search(rhs)
            if m:
                return m.group(0)
        return None

    def contains_tainted(rhs: str):
        for var, info in tainted.items():
            if re.search(rf'\b{re.escape(var)}\b', rhs):
                return info
        return None

    # Pass 1: propagate taint through direct assignments, concatenation,
    # f-strings, formatting, and other expressions containing a tainted var.
    for line_no, line in enumerate(lines, 1):
        m = assignment_re.match(line)
        if not m:
            continue

        var, rhs = m.groups()
        src = source_match(rhs)

        if src:
            tainted[var] = {"source": src, "line": line_no}
            continue

        inherited = contains_tainted(rhs)
        if inherited:
            tainted[var] = {
                "source": inherited["source"],
                "line": inherited["line"],
            }

    # Pass 2: direct source/sink and variable/sink flows.
    sink_specs = list(TAINT_SINKS.get(language, []))

    if language == "python":
        sink_specs += [
            (
                re.compile(r'\brequests\.(?:get|post|put|patch|delete|request)\s*\((.*)\)'),
                "requests HTTP request", "CWE-918", "HIGH"
            ),
            (
                re.compile(r'\b(?:urllib\.request\.)?urlopen\s*\((.*)\)'),
                "urlopen()", "CWE-918", "HIGH"
            ),
            (
                re.compile(r'\b(?:cursor|conn|connection)\.execute\s*\((.*)\)'),
                "SQL execute", "CWE-89", "CRITICAL"
            ),
        ]

    for line_no, line in enumerate(lines, 1):
        for sink_re, sink_name, cwe, severity in sink_specs:
            match = sink_re.search(line)
            if not match:
                continue

            arg = (match.group(1) if match.lastindex else line).strip()

            # Parameterized SQL is not SQL injection just because a bound value
            # originated from a request. Detect placeholders + a separate params
            # tuple/list and skip the taint finding.
            # Parameterized SQL is not SQL injection.
            if cwe == "CWE-89":
                has_fstring = bool(re.search(r'\bf["\']', arg))
                has_concat = "+" in arg
                # If there's a comma in the args, they are passing a parameter tuple: execute(query, params)
                has_params_tuple = "," in arg
                has_placeholder = bool(re.search(r'\?|%s|\:[A-Za-z_][A-Za-z0-9_]*', arg))

                # If it uses a tuple OR an inline placeholder, and NO f-strings/concat, it is safe.
                if (has_params_tuple or has_placeholder) and not has_fstring and not has_concat:
                    continue

            source_info = contains_tainted(arg)
            direct_source = source_match(arg)

            if not source_info and not direct_source:
                continue

            source_text = direct_source or source_info["source"]
            source_line = line_no if direct_source else source_info["line"]

            findings.append(
                DiagnosticItem(
                    type=severity,
                    severity=severity,
                    confidence=0.98 if direct_source else 0.96,
                    message=f"Confirmed tainted data flow into {sink_name}.",
                    lineStart=line_no,
                    lineEnd=line_no,
                    cwe=cwe,
                    owasp=OWASP_BY_CWE.get(cwe),
                    source=["TaintFlow"],
                    evidence=(
                        f"Untrusted source at line {source_line}: {source_text} "
                        f"flows into sink {sink_name} at line {line_no}."
                    ),
                    attackPath=[
                        f"source: {source_text}",
                        "tainted variable",
                        f"sink: {sink_name}",
                    ],
                    remediation=(
                        "Validate or constrain the input before it reaches the sink. "
                        "For SQL, use parameterized queries; for outbound HTTP, "
                        "allowlist schemes and destinations."
                    ),
                )
            )

    return findings


def run_static_checks(code: str, language: str) -> List[DiagnosticItem]:
    findings = run_pattern_checks(code, language)
    findings += run_taint_checks(code, language)
    if language.lower() in {"c", "h"}:
        findings += run_c_ast_checks(code)
    return findings


# ---------------------------------------------------------------------------
# Semgrep (unchanged)
# ---------------------------------------------------------------------------

LANG_TO_EXT = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
    "go": ".go",
    "rust": ".rs",
    "php": ".php",
    "ruby": ".rb",
    "csharp": ".cs",
}


def run_semgrep_sync(
    code: str,
    language: str,
    file_name: Optional[str],
) -> List[DiagnosticItem]:
    semgrep = shutil.which("semgrep")
    if not semgrep:
        return []

    ext = os.path.splitext(file_name or "")[1]
    if not ext:
        ext = LANG_TO_EXT.get(language.lower(), ".txt")

    try:
        with tempfile.TemporaryDirectory(prefix="vibeguard-") as tmp:
            path = os.path.join(tmp, f"snippet{ext}")

            with open(path, "w", encoding="utf-8") as f:
                f.write(code)

            result = subprocess.run(
                [
                    semgrep,
                    "scan",
                    "--config",
                    SEMGREP_CONFIG,
                    "--json",
                    "--quiet",
                    "--no-git-ignore",
                    path,
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            findings = []

            for item in data.get("results", []):
                start = item.get("start", {}).get("line", 1)
                end = item.get("end", {}).get("line", start)
                extra = item.get("extra", {}) or {}
                metadata = extra.get("metadata", {}) or {}

                severity = normalize_severity(
                    metadata.get("severity")
                    or extra.get("severity")
                    or "MEDIUM"
                )

                cwe = metadata.get("cwe", "CWE-Other")
                if isinstance(cwe, list):
                    cwe = cwe[0] if cwe else "CWE-Other"

                owasp = metadata.get("owasp")
                if isinstance(owasp, list):
                    owasp = owasp[0] if owasp else None

                if not owasp:
                    owasp = OWASP_BY_CWE.get(cwe)

                findings.append(
                    DiagnosticItem(
                        type=severity,
                        severity=severity,
                        confidence=0.95,
                        message=(
                            extra.get("message")
                            or item.get("check_id")
                            or "Semgrep finding"
                        ),
                        lineStart=start,
                        lineEnd=end,
                        cwe=cwe,
                        owasp=owasp,
                        source=["Semgrep"],
                        evidence=extra.get("lines", ""),
                        remediation=(
                            extra.get("fix")
                            or metadata.get("fix")
                            or "Review the Semgrep finding and apply the recommended secure pattern."
                        ),
                    )
                )

            return findings

    except Exception as exc:
        print(f"[Semgrep] unavailable/degraded: {exc}")
        return []


async def run_semgrep(
    code: str,
    language: str,
    file_name: Optional[str],
) -> List[DiagnosticItem]:
    return await asyncio.to_thread(
        run_semgrep_sync,
        code,
        language,
        file_name,
    )


# ---------------------------------------------------------------------------
# Lightweight secret scanner (unchanged)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Private key material detected.",
        "CWE-798",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Possible AWS access key detected.",
        "CWE-798",
    ),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"
        ),
        "Possible hardcoded credential or secret detected.",
        "CWE-798",
    ),
]


def run_secret_checks(code: str) -> List[DiagnosticItem]:
    diagnostics = []

    for line_no, line in enumerate(code.splitlines(), start=1):
        for pattern, message, cwe in SECRET_PATTERNS:
            if pattern.search(line):
                diagnostics.append(
                    DiagnosticItem(
                        type="CRITICAL",
                        severity="CRITICAL",
                        confidence=0.92,
                        message=message,
                        lineStart=line_no,
                        lineEnd=line_no,
                        cwe=cwe,
                        owasp="A07:2025-Authentication Failures",
                        source=["SecretScanner"],
                        evidence="Potential credential material appears directly in source code.",
                        remediation=(
                            "Move the secret to a secure secret manager or environment "
                            "variable and rotate the exposed credential."
                        ),
                    )
                )

    return diagnostics


# ---------------------------------------------------------------------------
# Dependency inventory (unchanged)
# ---------------------------------------------------------------------------

PY_STDLIB_MODULES = set(getattr(sys, "stdlib_module_names", ()))
PY_STDLIB_MODULES |= {
    "os", "sys", "re", "json", "time", "math", "random", "itertools",
    "functools", "collections", "subprocess", "threading", "asyncio",
    "typing", "pathlib", "uuid", "hashlib", "logging", "shutil", "socket",
    "http", "urllib", "datetime", "csv", "sqlite3", "unittest", "argparse",
    "io", "copy", "enum", "abc", "pickle", "struct", "traceback", "signal",
    "string", "textwrap", "glob", "tempfile", "queue", "multiprocessing",
}

NODE_BUILTIN_MODULES = {
    "fs", "path", "http", "https", "child_process", "crypto", "os", "url",
    "util", "events", "stream", "net", "dns", "readline", "assert", "zlib",
}


def extract_dependencies(
    code: str,
    language: str,
    file_name: Optional[str],
) -> List[str]:
    """Extract third-party dependency names. Distinguishes actual manifest
    files (package.json, requirements.txt) from plain source files, so
    source code lines like `import os` or `os.system(...)` never get
    mis-parsed as pip/npm package specs."""
    deps: List[str] = []
    language = language.lower()
    name = (file_name or "").lower()

    if name.endswith("package.json"):
        for match in re.finditer(r'"([^"]+)"\s*:\s*"([^"]+)"', code):
            pkg, version = match.groups()
            if pkg.startswith("@") or re.match(r"^[A-Za-z0-9_.-]+$", pkg):
                if pkg not in {"name", "version", "description", "main", "license"}:
                    deps.append(f"{pkg}@{version}")
        return deps[:100]

    if name.endswith("requirements.txt") or name.endswith(".txt"):
        for line in code.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=)?\s*([0-9][^ ]*)?", line)
            if m and m.group(1):
                deps.append(f"{m.group(1)}@{m.group(3) or 'unspecified'}")
        return deps[:100]

    if language == "python":
        seen = set()
        for m in re.finditer(r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_.]*)", code, re.MULTILINE):
            root_pkg = m.group(1).split(".")[0]
            if root_pkg in PY_STDLIB_MODULES or root_pkg in seen:
                continue
            seen.add(root_pkg)
            deps.append(f"{root_pkg}@unspecified")
        return deps[:100]

    if language in {"javascript", "typescript"}:
        seen = set()
        pattern = re.compile(
            r"""(?:import\s+(?:[\w{}*\s,]+\s+from\s+)?|require\()\s*['"]([^'"]+)['"]"""
        )
        for m in pattern.finditer(code):
            pkg = m.group(1)
            if pkg.startswith(".") or pkg.startswith("/"):
                continue
            if pkg.startswith("@"):
                parts = pkg.split("/")
                pkg = "/".join(parts[:2]) if len(parts) > 1 else pkg
            else:
                pkg = pkg.split("/")[0]
            if pkg in NODE_BUILTIN_MODULES or pkg in seen:
                continue
            seen.add(pkg)
            deps.append(f"{pkg}@unspecified")
        return deps[:100]

    return deps[:100]


# ---------------------------------------------------------------------------
# Package hallucination / slopsquatting detector (unchanged)
# ---------------------------------------------------------------------------

REGISTRY_URLS = {
    "python": "https://pypi.org/pypi/{name}/json",
    "javascript": "https://registry.npmjs.org/{name}",
    "typescript": "https://registry.npmjs.org/{name}",
}


async def _package_exists(name: str, language: str, client: httpx.AsyncClient) -> bool:
    cache_key = f"{language}:{name}"
    if cache_key in _PKG_EXIST_CACHE:
        return _PKG_EXIST_CACHE[cache_key]

    url_template = REGISTRY_URLS.get(language)
    if not url_template:
        _PKG_EXIST_CACHE[cache_key] = True
        return True

    try:
        resp = await client.get(url_template.format(name=name), timeout=2.5)
        exists = resp.status_code == 200
    except Exception:
        exists = True

    _PKG_EXIST_CACHE[cache_key] = exists
    return exists


async def check_hallucinated_packages(
    deps: List[str],
    language: str,
) -> List[DiagnosticItem]:
    language = language.lower()
    if language not in REGISTRY_URLS or not deps:
        return []

    skip_set = PY_STDLIB_MODULES if language == "python" else NODE_BUILTIN_MODULES
    names = [
        d.split("@")[0].strip()
        for d in deps
        if d.split("@")[0].strip() and d.split("@")[0].strip() not in skip_set
    ]
    if not names:
        return []

    diagnostics = []
    try:
        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(
                *[_package_exists(n, language, client) for n in names],
                return_exceptions=True,
            )

        for name, exists in zip(names, results):
            if exists is True:
                continue
            diagnostics.append(
                DiagnosticItem(
                    type="HIGH",
                    severity="HIGH",
                    confidence=0.75,
                    message=(
                        f"Package '{name}' was not found on the public registry. "
                        "This may be an AI-hallucinated dependency name, which is "
                        "a slopsquatting risk if later claimed by an attacker."
                    ),
                    cwe="CWE-1395",
                    owasp="A03:2025-Software Supply Chain Failures",
                    source=["DependencyCheck"],
                    evidence=f"No registry entry for '{name}'.",
                    attackPath=[
                        "AI suggests nonexistent package",
                        "developer installs it",
                        "attacker later publishes malicious package under that name",
                    ],
                    remediation=(
                        "Verify this dependency actually exists and is the intended "
                        "package before installing. Double check spelling against "
                        "the official registry."
                    ),
                )
            )
    except Exception as exc:
        print(f"[DependencyCheck] degraded: {exc}")

    return diagnostics


# ---------------------------------------------------------------------------
# LLM JSON helpers
# ---------------------------------------------------------------------------

def extract_json(text: str) -> Optional[dict]:
    if not text:
        return None

    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    fenced = re.search(
        r"```json\s*(\{.*?\})\s*```",
        text,
        re.DOTALL | re.IGNORECASE,
    )

    candidates = [fenced.group(1)] if fenced else []

    for start_match in re.finditer(r"\{", text):
        start = start_match.start()
        depth = 0
        in_string = False
        escaped = False

        for i in range(start, len(text)):
            ch = text[i]

            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start : i + 1])
                    break

    for candidate in candidates:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue

    return None


def build_security_prompt(
    code: str,
    language: str,
    user_prompt: str,
    evidence: Dict[str, Any],
) -> str:
    # This call's ONLY job is to correlate deterministic evidence into
    # labeled, explained findings. It deliberately does NOT ask for
    # fixed_code: cramming "write the entire corrected file" into the same
    # small, fast, multi-finding correlation call was why the model
    # compressed the fix down to a placeholder. Fix generation is a
    # separate, dedicated call -- see generate_fix_with_llm / POST /fix.
    compact_evidence = {
        "ast_findings": [
            {"line": f["lineStart"], "msg": f["message"], "cwe": f["cwe"]}
            for f in evidence.get("ast_findings", [])
        ],
        "taint_findings": [
            {
                "line": f["lineStart"],
                "msg": f["message"],
                "cwe": f["cwe"],
                "evidence": f.get("evidence", ""),
                "attack_path": f.get("attackPath", []),
            }
            for f in evidence.get("taint_findings", [])
        ],
        "semgrep_findings": [
            {"line": f["lineStart"], "msg": f["message"], "cwe": f["cwe"]}
            for f in evidence.get("semgrep_findings", [])
        ],
        "secret_findings": [
            {"line": f["lineStart"], "msg": f["message"]}
            for f in evidence.get("secret_findings", [])
        ],
        "sandbox_flags": {
            "network": bool(evidence.get("sandbox", {}).get("networkAttempts")),
            "files": bool(evidence.get("sandbox", {}).get("filesCreated")),
            "processes": bool(evidence.get("sandbox", {}).get("processesSpawned")),
        },
    }

    return f"""You are VibeGuard, a senior application-security reviewer.

Correlate the source code with the deterministic evidence below. Only report
a vulnerability when there is a plausible security issue. Distinguish
CONFIRMED vs POTENTIAL using confidence. Never invent CVE identifiers. Use
CWE ids and OWASP Top 10:2025 categories. Return exact line numbers. Keep
explanations short. If nothing is supported, return an empty findings array.

IMPORTANT SQL RULE:
- Do NOT report SQL injection merely because a value originated from user input.
- Parameterized/prepared SQL such as execute("SELECT ... WHERE id = ?", (user_id,))
  is SAFE against SQL injection unless there is another explicit flaw.
- Report CWE-89 when untrusted data is interpolated/concatenated/formatted into
  SQL syntax itself (for example f-strings or "SELECT ..." + user_id).

User intent: {user_prompt}
Language: {language}

Source code:
---BEGIN CODE---
{code[:6000]}
---END CODE---

Evidence:
{json.dumps(compact_evidence)}

Return ONLY valid JSON, no prose, matching:
{{"findings":[{{"title":"","severity":"CRITICAL|HIGH|MEDIUM|LOW","confidence":0.9,"line_start":1,"line_end":1,"cwe":"CWE-89","owasp":"A05:2025-Injection","status":"CONFIRMED|POTENTIAL","evidence":"","attack_path":[],"explanation":"","remediation":""}}],"scope_drift_score":0.0,"scope_drift_reason":""}}""".strip()


async def call_ibm_watsonx(
    system_prompt: str,
    max_tokens: Optional[int] = None,
    timeout: Optional[float] = None,
) -> Optional[dict]:
    token = os.getenv("IBM_BEARER_TOKEN")
    project_id = os.getenv("IBM_PROJECT_ID")

    if not token or not project_id:
        return None

    try:
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = {
            "input": system_prompt,
            "model_id": IBM_MODEL_ID,
            "project_id": project_id,
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": max_tokens or LLM_MAX_TOKENS,
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                IBM_URL,
                json=payload,
                headers=headers,
                timeout=timeout or IBM_TIMEOUT,
            )

        if response.status_code != 200:
            print(f"[IBM] degraded: HTTP {response.status_code}")
            return None

        results = response.json().get("results", [])
        if not results:
            return None

        return extract_json(results[0].get("generated_text", ""))

    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        print(f"[IBM] timed out/unreachable, falling back: {exc}")
        return None
    except Exception as exc:
        print(f"[IBM] connection failed: {exc}")
        return None


async def call_local_llama(
    system_prompt: str,
    max_tokens: Optional[int] = None,
    num_ctx: int = 4096,
    timeout: Optional[float] = None,
) -> Optional[dict]:
    """Call Ollama / Llama 3.3 in fast JSON chat mode.

    max_tokens / num_ctx / timeout are overridable per-call so the small,
    fast /analyze correlation call and the larger /fix generation call
    don't have to share one flat budget -- that mismatch (fix generation
    starved to the same 450-token, 4096-ctx budget as correlation) was the
    root cause of placeholder fixes on anything non-trivial.
    """
    try:
        url = f"{GPU_TUNNEL_URL}/api/chat"

        payload = {
            "model": LLAMA_MODEL,
            "messages": [{"role": "user", "content": system_prompt}],
            "stream": False,
            "format": "json",
            "keep_alive": "30m",
            "options": {
                "temperature": 0.1,
                "num_predict": max_tokens or LLM_MAX_TOKENS,
                "num_ctx": num_ctx,
                "top_k": 20,
                "top_p": 0.9,
            },
        }

        headers = {
            "ngrok-skip-browser-warning": "true",
            "User-Agent": "VibeGuard/2.4",
            "Content-Type": "application/json",
        }

        start_time = time.perf_counter()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout or LLAMA_TIMEOUT,
            )

        elapsed = time.perf_counter() - start_time
        print(f"[Llama3.3] HTTP {response.status_code} in {elapsed:.2f}s "
              f"(num_predict={payload['options']['num_predict']}, num_ctx={num_ctx})", flush=True)

        if response.status_code != 200:
            print(f"[Llama3.3] Response error: {response.text[:500]}", flush=True)
            return None

        data = response.json()
        raw_content = data.get("message", {}).get("content", "") or ""

        result = extract_json(raw_content)
        if result:
            return result

        print("[Llama3.3] Could not parse JSON:", raw_content[:500], flush=True)
        return None

    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        print(f"[Llama3.3] timed out/unreachable: {exc}", flush=True)
        return None
    except Exception as exc:
        print(f"[Llama3.3] ERROR {type(exc).__name__}: {repr(exc)}", flush=True)
        return None


def _cache_key(code: str, language: str, user_prompt: str) -> str:
    h = hashlib.sha256()
    h.update(language.lower().encode())
    h.update(b"|")
    h.update(user_prompt.encode())
    h.update(b"|")
    h.update(code.encode())
    return h.hexdigest()


async def analyze_security_with_llm(
    code: str,
    language: str,
    prompt: str,
    evidence: Dict[str, Any],
) -> tuple[Optional[dict], str]:

    key = _cache_key(code, language, prompt)
    cached = _LLM_CACHE.get(key)
    if cached:
        return cached["result"], cached["engine"] + " (cached)"

    system_prompt = build_security_prompt(
        code=code,
        language=language,
        user_prompt=prompt,
        evidence=evidence,
    )

    result, engine = None, "none"

    print("[AI Routing] Trying local Llama 3.3...")
    llama = await call_local_llama(system_prompt)
    if llama:
        result, engine = llama, "Llama-3.3-Local"
    else:
        print("[AI Routing] Local Llama unavailable; trying IBM Watsonx...")
        ibm = await call_ibm_watsonx(system_prompt)
        if ibm:
            result, engine = ibm, "IBM Watsonx"

    if result:
        if len(_LLM_CACHE) >= _LLM_CACHE_MAX:
            _LLM_CACHE.pop(next(iter(_LLM_CACHE)))
        _LLM_CACHE[key] = {"result": result, "engine": engine}

    return result, engine


SECURITY_SENSITIVE_PATTERNS = [
    r'\bjwt\.(?:decode|encode)\s*\(',
    r'verify_signature\s*[:=]\s*False',
    r'\bhashlib\.(?:md5|sha1|sha256|sha512)\s*\(',
    r'\b(?:requests|urllib)\.(?:get|post|put|patch|delete|request|urlopen)\s*\(',
    r'\b(?:cursor|conn|connection)\.execute\s*\(',
    r'\b(?:os\.system|os\.popen|subprocess\.|eval\s*\(|exec\s*\(|pickle\.loads?|yaml\.load)\b',
    r'\b(?:innerHTML|outerHTML)\b',
    r'\b(?:password|passwd|secret|api[_-]?key|token)\b',
]

def security_sensitive_heuristic(code: str) -> bool:
    return any(re.search(pattern, code, re.I) for pattern in SECURITY_SENSITIVE_PATTERNS)


def scope_drift_heuristic(user_prompt: str, code: str) -> bool:
    sensitive = ["exec", "eval", "subprocess", "os.system", "pickle.load",
                 "requests.get", "socket", "shell=True", "child_process"]
    lower_code = code.lower()
    lower_prompt = user_prompt.lower()
    for kw in sensitive:
        if kw.lower() in lower_code and kw.lower().split(".")[0] not in lower_prompt:
            return True
    return False


# ---------------------------------------------------------------------------
# Sandbox (unchanged)
# ---------------------------------------------------------------------------

async def analyze_with_sandbox(
    code: str,
    language: str = "python",
) -> dict:

    if not SANDBOX_URL:
        return {
            "available": False,
            "sandbox_risk_score": 0.0,
            "reason": "Sandbox URL not configured.",
            "networkAttempts": [],
            "filesCreated": [],
            "processesSpawned": [],
            "duration_ms": 0,
        }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                SANDBOX_URL,
                json={"code": code, "language": language},
                headers={"ngrok-skip-browser-warning": "true"},
                timeout=SANDBOX_TIMEOUT,
            )

        if response.status_code != 200:
            return {
                "available": False,
                "sandbox_risk_score": 0.0,
                "reason": f"Sandbox HTTP error: {response.status_code}",
                "networkAttempts": [],
                "filesCreated": [],
                "processesSpawned": [],
                "duration_ms": 0,
            }

        data = response.json()

        return {
            "available": True,
            "sandbox_risk_score": 0.0,
            "reason": "Sandbox telemetry collected.",
            "stdout": data.get("stdout", ""),
            "duration_ms": data.get("durationMs", 0),
            "networkAttempts": data.get("networkAttempts", []),
            "filesCreated": data.get("filesCreated", []),
            "processesSpawned": data.get("processesSpawned", []),
        }

    except Exception as exc:
        print(f"[Sandbox] degraded: {exc}")
        return {
            "available": False,
            "sandbox_risk_score": 0.0,
            "reason": "Sandbox offline or timed out.",
            "networkAttempts": [],
            "filesCreated": [],
            "processesSpawned": [],
            "duration_ms": 0,
        }


def sandbox_to_diagnostics(sandbox: dict) -> List[DiagnosticItem]:
    diagnostics = []

    network = sandbox.get("networkAttempts", [])
    files = sandbox.get("filesCreated", [])
    processes = sandbox.get("processesSpawned", [])
    duration = sandbox.get("duration_ms", 0)

    if network:
        diagnostics.append(
            DiagnosticItem(
                type="HIGH",
                severity="HIGH",
                confidence=0.90,
                message="Sandbox observed outbound network activity.",
                cwe="CWE-918",
                owasp="A01:2025-Broken Access Control",
                source=["Sandbox"],
                evidence=f"Observed network attempts: {network}",
                attackPath=["program execution", "outbound network activity"],
                remediation=(
                    "Review whether outbound network access is expected and "
                    "restrict destinations where possible."
                ),
            )
        )

    if files:
        diagnostics.append(
            DiagnosticItem(
                type="MEDIUM",
                severity="MEDIUM",
                confidence=0.85,
                message="Sandbox observed file creation or modification.",
                cwe="CWE-73",
                owasp="A02:2025-Security Misconfiguration",
                source=["Sandbox"],
                evidence=f"Observed file operations: {files}",
                remediation=(
                    "Verify that filesystem writes are intended and apply "
                    "least-privilege filesystem permissions."
                ),
            )
        )

    if processes:
        diagnostics.append(
            DiagnosticItem(
                type="CRITICAL",
                severity="CRITICAL",
                confidence=0.95,
                message="Sandbox observed process or shell execution.",
                cwe="CWE-78",
                owasp="A05:2025-Injection",
                source=["Sandbox"],
                evidence=f"Observed processes: {processes}",
                attackPath=["program execution", "process/shell spawn"],
                remediation=(
                    "Avoid shell execution with untrusted input and restrict "
                    "process creation privileges."
                ),
            )
        )

    if duration and duration > 5000:
        diagnostics.append(
            DiagnosticItem(
                type="HIGH",
                severity="HIGH",
                confidence=0.80,
                message="Sandbox execution exceeded the expected time budget.",
                cwe="CWE-400",
                owasp="A10:2025-Mishandling of Exceptional Conditions",
                source=["Sandbox"],
                evidence=f"Execution duration: {duration} ms",
                remediation=(
                    "Investigate unbounded loops, resource exhaustion and "
                    "missing execution limits."
                ),
            )
        )

    return diagnostics


# ---------------------------------------------------------------------------
# Finding normalization / correlation
# ---------------------------------------------------------------------------

def normalize_cwe_for_vibeguard(cwe: str, message: str, evidence: str) -> str:
    cwe = cwe or "CWE-Other"
    blob = f"{message} {evidence}".lower()

    # Normalize common model misclassification for JWT signature verification.
    if (
        cwe == "CWE-345"
        and ("jwt" in blob or "signature" in blob or "verify_signature" in blob)
    ):
        return "CWE-347"

    if cwe == "CWE-327" and "md5" in blob:
        return "CWE-328"

    return cwe


def normalize_ai_findings(ai_result: Optional[dict]) -> List[DiagnosticItem]:
    if not ai_result:
        return []

    findings = ai_result.get("findings", [])
    if not isinstance(findings, list):
        return []

    normalized = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(finding.get("severity"))
        raw_message = finding.get("title") or "Potential security vulnerability"
        raw_evidence = finding.get("evidence") or finding.get("explanation") or ""
        cwe = normalize_cwe_for_vibeguard(
            finding.get("cwe") or "CWE-Other",
            raw_message,
            raw_evidence,
        )
        owasp = OWASP_BY_CWE.get(cwe) or finding.get("owasp")

        try:
            start = max(1, int(finding.get("line_start", 1)))
            end = max(start, int(finding.get("line_end", start)))
        except (TypeError, ValueError):
            start, end = 1, 1

        normalized.append(
            DiagnosticItem(
                type=severity,
                severity=severity,
                confidence=clamp_confidence(finding.get("confidence", 0.5)),
                message=finding.get("title") or "Potential security vulnerability",
                lineStart=start,
                lineEnd=end,
                cwe=cwe,
                owasp=owasp,
                source=["LLM"],
                evidence=finding.get("evidence") or finding.get("explanation"),
                attackPath=finding.get("attack_path") or [],
                remediation=finding.get("remediation"),
                # fixedCode is intentionally NOT populated here. The
                # correlation prompt no longer asks for it (see
                # build_security_prompt) -- fix generation is /fix's job,
                # where it gets a dedicated token/context budget and a
                # verified-or-rejected loop. This field stays None so the
                # frontend always calls /fix for a real fix instead of
                # rendering an unverified, possibly-truncated one inline.
                fixedCode=None,
            )
        )

    return normalized


def deduplicate_findings(
    findings: List[DiagnosticItem],
) -> List[DiagnosticItem]:
    """
    Merge multiple detectors reporting the same underlying vulnerability.
    CWE + nearby source location is the primary correlation key since
    Pattern, TaintFlow and LLM often describe the same issue differently.
    """
    result: List[DiagnosticItem] = []

    for finding in findings:
        duplicate = None

        for existing in result:
            same_cwe = bool(finding.cwe) and finding.cwe == existing.cwe
            nearby = (
                abs(finding.lineStart - existing.lineStart) <= 2
                or (
                    finding.lineStart <= existing.lineEnd + 2
                    and existing.lineStart <= finding.lineEnd + 2
                )
            )

            if same_cwe and nearby:
                duplicate = existing
                break

        if duplicate:
            duplicate.source = sorted(
                set(duplicate.source + finding.source)
            )

            source_count = len(set(duplicate.source))
            duplicate.confidence = min(
                0.99,
                max(duplicate.confidence, finding.confidence)
                + (0.03 if source_count >= 2 else 0.0)
                + (0.02 if source_count >= 3 else 0.0),
            )

            if len(finding.evidence or "") > len(duplicate.evidence or ""):
                duplicate.evidence = finding.evidence

            if len(finding.attackPath or []) > len(duplicate.attackPath or []):
                duplicate.attackPath = finding.attackPath

            if len(finding.remediation or "") > len(duplicate.remediation or ""):
                duplicate.remediation = finding.remediation

            if not duplicate.fixedCode and finding.fixedCode:
                duplicate.fixedCode = finding.fixedCode

            rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if rank.get(finding.severity or "", 0) > rank.get(
                duplicate.severity or "", 0
            ):
                duplicate.severity = finding.severity
                duplicate.type = finding.type

        else:
            result.append(finding.model_copy(deep=True))

    return result


def correlate_findings(
    static_findings: List[DiagnosticItem],
    semgrep_findings: List[DiagnosticItem],
    secret_findings: List[DiagnosticItem],
    sandbox_findings: List[DiagnosticItem],
    dependency_findings: List[DiagnosticItem],
    ai_findings: List[DiagnosticItem],
) -> List[DiagnosticItem]:

    findings = deduplicate_findings(
        static_findings
        + semgrep_findings
        + secret_findings
        + sandbox_findings
        + dependency_findings
        + ai_findings
    )

    for finding in findings:
        if len(finding.source) >= 2:
            finding.confidence = min(
                0.99,
                finding.confidence + 0.08,
            )

        if finding.cwe and finding.owasp is None:
            finding.owasp = OWASP_BY_CWE.get(finding.cwe)

    return findings


def calculate_risk(findings: List[DiagnosticItem]) -> float:
    if not findings:
        return 0.0

    weighted = sorted(
        [
            SEVERITY_SCORE.get(
                normalize_severity(f.severity),
                0.0,
            )
            * f.confidence
            for f in findings
        ],
        reverse=True,
    )

    score = weighted[0] if weighted else 0.0

    for extra in weighted[1:3]:
        score += extra * 0.15

    return round(min(score, 10.0), 2)


# ---------------------------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze_code(payload: CodePayload):
    exec_id = f"run_{uuid.uuid4().hex[:8]}"
    user_prompt = payload.userPrompt or "Write safe, production-ready code."
    t0 = time.perf_counter()

    static_findings = run_static_checks(
        payload.codeSnippet,
        payload.language,
    )

    dependencies = extract_dependencies(
        payload.codeSnippet,
        payload.language,
        payload.fileName,
    )

    semgrep_findings, secret_findings, sandbox_results, dependency_findings = await asyncio.gather(
        run_semgrep(
            payload.codeSnippet,
            payload.language,
            payload.fileName,
        ),
        asyncio.to_thread(
            run_secret_checks,
            payload.codeSnippet,
        ),
        analyze_with_sandbox(
            payload.codeSnippet,
            payload.language,
        ),
        check_hallucinated_packages(
            dependencies,
            payload.language,
        ),
    )

    sandbox_findings = sandbox_to_diagnostics(sandbox_results)

    deterministic_findings = (
        static_findings + semgrep_findings + secret_findings
        + sandbox_findings + dependency_findings
    )

    has_deterministic = len(deterministic_findings) >= STATIC_FINDINGS_THRESHOLD
    has_scope_drift = scope_drift_heuristic(user_prompt, payload.codeSnippet)
    has_sensitive_code = security_sensitive_heuristic(payload.codeSnippet)

    needs_llm = has_deterministic or has_scope_drift or has_sensitive_code

    if has_deterministic:
        llm_reason = "deterministic-finding"
    elif has_scope_drift:
        llm_reason = "scope-drift"
    elif has_sensitive_code:
        llm_reason = "security-sensitive-code"
    else:
        llm_reason = "not-needed"

    ai_result, ai_engine = None, "skipped-clean"
    if needs_llm:
        evidence = {
            "ast_findings": [d.model_dump() for d in static_findings if "AST" in d.source],
            "taint_findings": [d.model_dump() for d in static_findings if "TaintFlow" in d.source],
            "pattern_findings": [d.model_dump() for d in static_findings if "Pattern" in d.source],
            "semgrep_findings": [d.model_dump() for d in semgrep_findings],
            "secret_findings": [d.model_dump() for d in secret_findings],
            "dependency_findings": [d.model_dump() for d in dependency_findings],
            "sandbox": sandbox_results,
        }

        ai_result, ai_engine = await analyze_security_with_llm(
            code=payload.codeSnippet,
            language=payload.language,
            prompt=user_prompt,
            evidence=evidence,
        )

    ai_findings = normalize_ai_findings(ai_result)

    findings = correlate_findings(
        static_findings,
        semgrep_findings,
        secret_findings,
        sandbox_findings,
        dependency_findings,
        ai_findings,
    )

    scope_score = 0.0
    scope_reason = ""

    if ai_result:
        try:
            scope_score = float(ai_result.get("scope_drift_score", 0.0))
        except (TypeError, ValueError):
            scope_score = 0.0
        scope_reason = ai_result.get("scope_drift_reason", "")

    if scope_score >= 7.0:
        findings.append(
            DiagnosticItem(
                type="MEDIUM",
                severity="MEDIUM",
                confidence=min(0.95, scope_score / 10.0),
                message=(
                    "AI-generated code may significantly deviate "
                    "from the requested behavior."
                ),
                lineStart=1,
                lineEnd=1,
                cwe="CWE-841",
                owasp="A06:2025-Insecure Design",
                source=["LLM"],
                evidence=scope_reason,
                remediation=(
                    "Review generated functionality against the original "
                    "user request before accepting the change."
                ),
            )
        )

    findings = deduplicate_findings(findings)
    risk_score = calculate_risk(findings)

    summary = {
        "critical": sum(f.severity == "CRITICAL" for f in findings),
        "high": sum(f.severity == "HIGH" for f in findings),
        "medium": sum(f.severity == "MEDIUM" for f in findings),
        "low": sum(f.severity == "LOW" for f in findings),
    }

    analyzers = {
        "static": True,
        "semgrep": bool(shutil.which("semgrep")),
        "secrets": True,
        "sandbox": sandbox_results.get("available", False),
        "dependencyCheck": True,
        "llm": bool(ai_result),
    }

    status = (
        "CRITICAL" if summary["critical"]
        else "HIGH" if summary["high"]
        else "MEDIUM" if summary["medium"]
        else "LOW" if summary["low"]
        else (
            "ANALYSIS_UNAVAILABLE"
            if needs_llm and not ai_result
            else "SAFE"
        )
    )

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    return {
        "executionId": exec_id,
        "finalRiskScore": risk_score,
        "status": status,
        "aiEngine": ai_engine,
        "llmInvoked": needs_llm,
        "llmReason": llm_reason,
        "durationMs": elapsed_ms,
        "summary": summary,
        "dependencies": dependencies,
        "diagnostics": [d.model_dump() for d in findings],
        "sandbox": sandbox_results,
        "analyzers": analyzers,
        "correlation": {
            "multiSourceFindings": sum(
                1 for d in findings if len(set(d.source)) >= 2
            ),
            "confirmedFindings": [
                {
                    "cwe": d.cwe,
                    "lineStart": d.lineStart,
                    "lineEnd": d.lineEnd,
                    "sources": sorted(set(d.source)),
                    "confidence": d.confidence,
                }
                for d in findings
                if len(set(d.source)) >= 2
            ],
            "sources": sorted({source for d in findings for source in d.source}),
        },
    }


# ---------------------------------------------------------------------------
# AI fix + deterministic verification
# ---------------------------------------------------------------------------

PLACEHOLDER_PATTERNS = [
    r"\bvalidated_command\b",
    r"\bvalidated_args\b",
    r"\bYOUR_[A-Z0-9_]+\b",
    r"<[^>]+>",
    r"\.{3,}",
]


def is_placeholder_fix(fixed_code: Optional[str], original_code: str) -> bool:
    """Shared placeholder detector, used both to reject a bad /fix result
    and (via generate_fix_with_llm's retry) to catch it before we've
    already given up."""
    if not fixed_code or not fixed_code.strip():
        return True
    if fixed_code.strip() == original_code.strip():
        return True
    return any(re.search(pattern, fixed_code) for pattern in PLACEHOLDER_PATTERNS)


FIX_FEWSHOT_EXAMPLE = """
Example -- CWE-78 (os.system with tainted input):

Vulnerable:
cmd = request.args["cmd"]
os.system(cmd)

Correct fix (concrete, no placeholders):
ALLOWED_COMMANDS = {"status": ["systemctl", "status", "myapp"], "restart": ["systemctl", "restart", "myapp"]}
cmd_key = request.args.get("cmd")
if cmd_key not in ALLOWED_COMMANDS:
    abort(400, "Unknown command")
subprocess.run(ALLOWED_COMMANDS[cmd_key], shell=False, check=True)

Notice the fix does not "validate cmd" abstractly -- it replaces the
untrusted string with a concrete allowlist, because os.system() has no
safe way to pass through arbitrary attacker-controlled input at all. Apply
the same standard of concreteness to whatever CWE you are fixing: invent a
real allowlist, schema, bound, or parameterized call, not a description of
validation.
""".strip()


async def generate_fix_with_llm(
    code: str,
    language: str,
    finding: Dict[str, Any],
    user_prompt: str,
    _critique: Optional[str] = None,
) -> tuple[Optional[str], str]:
    finding_json = json.dumps(finding, ensure_ascii=False)

    critique_block = ""
    if _critique:
        critique_block = f"""
Your previous attempt was rejected: {_critique}
Do not repeat that mistake. Write the actual concrete logic (allowlists,
parameterized calls, bounded buffers, etc.) -- never a variable name that
implies validation happened somewhere else.
"""

    prompt = f"""
You are VibeGuard's secure-code fixer.

Fix ONLY the security issue described below. Preserve the requested behavior
and all unrelated code. Return ONLY valid JSON.

{FIX_FEWSHOT_EXAMPLE}

IMPORTANT:
- Return the COMPLETE corrected source code, not a diff or a snippet.
- Use the actual variables and structure from the supplied source.
- Do NOT use placeholders such as "validated_command", "validated_args",
  "<input>", "YOUR_VALUE", "...", or pseudocode.
- If the safe fix requires an allowlist, schema, or bound, invent a concrete
  reasonable one (as in the example above) rather than gesturing at
  "validation".
- Do NOT invent unrelated functionality.
- The corrected code must directly address the reported CWE.
{critique_block}
Language: {language}
User intent: {user_prompt}

Finding:
{finding_json}

Source code:
---BEGIN CODE---
{code[:12000]}
---END CODE---

Return exactly:
{{"fixed_code":"<complete corrected source code>","explanation":"<short explanation>"}}
""".strip()

    budget = estimate_fix_token_budget(code)

    result = await call_local_llama(
        prompt,
        max_tokens=budget,
        num_ctx=FIX_NUM_CTX,
        timeout=FIX_TIMEOUT,
    )
    if result:
        return result.get("fixed_code"), "Llama-3.3-Local"

    result = await call_ibm_watsonx(prompt, max_tokens=budget, timeout=FIX_TIMEOUT)
    if result:
        return result.get("fixed_code"), "IBM Watsonx"

    return None, "none"


@app.post("/fix")
async def fix_code(payload: FixPayload):
    """
    Generate a security fix and immediately re-run deterministic analysis.
    Verification is deliberately deterministic: a fix is never called
    "verified" merely because the LLM said it was fixed.

    Placeholder fixes (undefined helper vars, "<...>" pseudocode, etc.) are
    caught before this even reaches deterministic re-analysis: one retry
    with an explicit critique is attempted first, since that alone reliably
    knocks out the lazy "validated_x" completion pattern.
    """
    t0 = time.perf_counter()
    user_prompt = payload.userPrompt or "Preserve the intended behavior while fixing the security issue."

    fixed_code, fix_engine = await generate_fix_with_llm(
        payload.codeSnippet,
        payload.language,
        payload.finding,
        user_prompt,
    )

    if is_placeholder_fix(fixed_code, payload.codeSnippet):
        print("[Fix] First attempt was a placeholder, retrying with critique...")
        fixed_code, fix_engine = await generate_fix_with_llm(
            payload.codeSnippet,
            payload.language,
            payload.finding,
            user_prompt,
            _critique="You returned a placeholder variable name instead of real code.",
        )

    if is_placeholder_fix(fixed_code, payload.codeSnippet):
        return {
            "status": "FIX_NOT_VERIFIABLE",
            "verified": False,
            "fixEngine": fix_engine,
            "fixedCode": fixed_code,
            "reason": "AI did not return a context-aware complete fix after retry.",
            "durationMs": round((time.perf_counter() - t0) * 1000, 1),
        }

    # Verify the returned code with the same deterministic stack.
    static_findings = run_static_checks(fixed_code, payload.language)
    dependencies = extract_dependencies(
        fixed_code, payload.language, payload.fileName
    )

    semgrep_findings, secret_findings, sandbox_results, dependency_findings = await asyncio.gather(
        run_semgrep(fixed_code, payload.language, payload.fileName),
        asyncio.to_thread(run_secret_checks, fixed_code),
        analyze_with_sandbox(fixed_code, payload.language),
        check_hallucinated_packages(dependencies, payload.language),
    )

    sandbox_findings = sandbox_to_diagnostics(sandbox_results)
    verified_findings = deduplicate_findings(
        static_findings
        + semgrep_findings
        + secret_findings
        + sandbox_findings
        + dependency_findings
    )

    original_cwe = payload.finding.get("cwe")

    matching = [
        f for f in verified_findings
        if original_cwe
        and f.cwe == original_cwe
        and normalize_severity(f.severity) in {"CRITICAL", "HIGH", "MEDIUM"}
    ]

    verified = len(matching) == 0
    verification_status = "VERIFIED_FIX" if verified else "FIX_NOT_VERIFIED"

    return {
        "status": verification_status,
        "verified": verified,
        "fixEngine": fix_engine,
        "fixedCode": fixed_code,
        "remainingDiagnostics": [f.model_dump() for f in verified_findings],
        "verification": {
            "originalCwe": original_cwe,
            "matchingFindingsRemaining": len(matching),
            "deterministicScannersRun": [
                "Pattern/AST/TaintFlow",
                "Semgrep",
                "SecretScanner",
                "DependencyCheck",
                "Sandbox",
            ],
        },
        "durationMs": round((time.perf_counter() - t0) * 1000, 1),
    }


@app.get("/health")
async def health():
    llama_reachable = False
    if GPU_TUNNEL_URL:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{GPU_TUNNEL_URL}/api/tags",
                    headers={"ngrok-skip-browser-warning": "true"},
                    timeout=2.0,
                )
                llama_reachable = response.status_code == 200
        except Exception:
            llama_reachable = False

    ibm_configured = bool(
        os.getenv("IBM_BEARER_TOKEN") and os.getenv("IBM_PROJECT_ID")
    )

    return {
        "status": "ok",
        "primaryEngine": "Llama-3.3-Local",
        "fallbackEngine": "IBM Watsonx",
        "llamaConfigured": bool(GPU_TUNNEL_URL),
        "llamaReachable": llama_reachable,
        "ibmConfigured": ibm_configured,
        "semgrepInstalled": bool(shutil.which("semgrep")),
        "sandboxConfigured": bool(SANDBOX_URL),
        "cacheSize": len(_LLM_CACHE),
        "fixTokenBudget": {"base": FIX_MAX_TOKENS_BASE, "cap": FIX_MAX_TOKENS_CAP, "numCtx": FIX_NUM_CTX},
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backendorch:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )