# Core Security Audit Methodology

Polyglot-audit employs a principled, evidence-based taint-reachability and vulnerability audit methodology.

## 1. Core Paradigm: Source -> Guard -> Sink

A candidate vulnerability exists when untrusted input flows from an external entry point (Source) to a critical operation (Sink) without effective, verifiable defenses (Guards).

1. **Source**: An untrusted external input (HTTP parameter, body, header, environment variable, RPC payload, CLI argument, or file input).
2. **Path**: An unbroken, traceable sequence of data propagations, function invocations, or parameter passes connecting source to sink.
3. **Guards**: Defensive mechanisms encountered along the path. A guard must be verified in the specific context of the path. Registered middleware does not grant universal immunity.
4. **Sink**: A sensitive API or operation capable of adverse security impact (Code Execution, Injection, Path Traversal, Memory Corruption, State Manipulation).

## 2. Evidence Standards: E1 vs E2

- **E1 (Incomplete Static Evidence)**: A credible taint flow identified, but missing critical runtime, environmental, or deployment context. Results in `needs_validation`.
- **E2 (Independent Static Proof)**: Full static path from source to sink verified with code anchors, unbroken parameter passing, absence or failure of guards, and clear preconditions. Results in `confirmed`.
- **E3**: Dynamic reproduction / exploit proof (prohibited in v1; static audit only).

## 3. Disqualification (What is NOT a candidate)

- General code smells, formatting quirks, or style deviations.
- Missing strict mode or unhandled errors on non-security-critical pathways.
- Hardcoded constants or trusted internal configuration data.
- Defended paths where sanitization or validation is conclusively active.
