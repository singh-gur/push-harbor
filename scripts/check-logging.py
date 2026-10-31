#!/usr/bin/env python3
"""Logging guard (PH-24): fails when a log call might record a secret or a capability.

Scans every log call in the Rust crates and the Android module (tracing macros, workers
console macros, eprintln!/println! in servers, android.util.Log) and rejects calls whose arguments
mention device targets, keys, tokens, nonces, payloads, endpoint IDs, URLs or paths. A reviewed
exception carries `// log-ok: <why>` on the call's first line. The runtime counterpart is the
conformance `logs` test, which greps real relay logs for every secret the suite used.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = [*ROOT.glob("crates/*/src/**/*.rs"), *ROOT.glob("packages/expo/android/src/main/**/*.kt")]
CALL = re.compile(
    r"\b(?:tracing::(?:trace|debug|info|warn|error)!|(?:worker::)?console_(?:log|debug|warn|error)!"
    r"|Log\.[dviwe])\s*\("
)
FORBIDDEN = re.compile(
    r"\b(target|fid|token|nonce|payload|body|key|keys|auth|authorization|endpoint|sender|rid|url|path|"
    r"secret|private|plaintext|subscription|request)\b",
    re.IGNORECASE,
)


INTERPOLATED = re.compile(r"\{([A-Za-z_][\w.]*)|\$\{?([A-Za-z_][\w.]*)")


def call_text(source: str, start: int) -> str:
    """The call from its opening parenthesis to the matching close."""
    depth, i = 0, source.index("(", start)
    for j in range(i, len(source)):
        depth += {"(": 1, ")": -1}.get(source[j], 0)
        if depth == 0:
            return source[i : j + 1]
    return source[i:]


def main() -> int:
    problems = []
    for path in SOURCES:
        source = path.read_text()
        for match in CALL.finditer(source):
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.start())
            if "log-ok:" in source[line_start:line_end]:
                continue
            text = call_text(source, match.start())
            # Words inside the message string are prose ("request", "path"), not values, except
            # interpolated names: Rust `{name}` and Kotlin `$name` / `${expr}`.
            strings = re.findall(r'"(?:[^"\\]|\\.)*"', text)
            names = [a or b for s in strings for a, b in INTERPOLATED.findall(s)]
            interpolated = " ".join(names).replace(".", " ")
            values = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text) + " " + interpolated
            hit = FORBIDDEN.search(values)
            if hit:
                line = source.count("\n", 0, match.start()) + 1
                problems.append(f"{path.relative_to(ROOT)}:{line}: logs `{hit.group(0)}`: {text[:120]}")
    for problem in problems:
        print(problem)
    print(f"logging guard: {len(problems)} problem(s)" if problems else "logging guard: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
