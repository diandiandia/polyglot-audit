"""Substantive per-card content for the Shell knowledge cards (shell-01..shell-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, bash manual nodes, POSIX specification).

Per the catalog draft, Shell entries are limited to security contexts:
privileged scripts, CI pipelines, install scripts, and setuid/root contexts.

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Shell section).
"""

LANGUAGE = {
    "name": "Shell",
    "prefix": "shell",
}

CARDS = [
    {
        "num": "01",
        "title": "Unquoted Variable Expansion and Word Splitting",
        "platform": "POSIX sh and bash on Linux/macOS; word splitting and pathname expansion semantics are identical in both, per POSIX Shell Command Language §2.6",
        "mechanism": (
            "An unquoted expansion is not a value but a string to be re-parsed: the "
            "shell first splits it on every character of IFS (default: space, tab, "
            "newline), then runs pathname expansion on each resulting word. An "
            "attacker-controlled filename containing spaces becomes two arguments, so "
            "'rm -rf $dir' with dir='/tmp/my docs' deletes '/tmp/my'; a value "
            "containing '*' expands against the current directory contents, so a "
            "filename shaped like a glob makes the shell choose its own operand list. "
            "Command substitution $(cmd) inherits the same re-parsing unless quoted."
        ),
        "source": (
            "Attacker-influenced strings reaching a privileged or CI script: untrusted "
            "filenames from a shared directory, branch/tag names from a VCS webhook, "
            "fields parsed from untrusted files, environment variables in a "
            "setuid-root or CI-runner context."
        ),
        "sink": (
            "Unquoted $var, ${var}, $(cmd) or ${arr[*]} expansions feeding destructive "
            "or security-relevant commands (rm -rf, chown, chmod, kill, cp, mv, "
            "installer invocations)"
        ),
        "guards": (
            "Check every expansion feeding a command is double-quoted (\"$var\", "
            "\"$(cmd)\", \"${arr[@]}\"); check destructive utilities get '--' before "
            "operand variables; check IFS is pinned or the loop uses 'while IFS= read "
            "-r'; for arrays verify \"${arr[@]}\" is used, never \"${arr[*]}\" in a "
            "single-string context."
        ),
        "not_candidate_when": (
            "The variable is assigned a compile-time constant in the same script with "
            "no external input on any assignment path, the expansion is quoted and "
            "the command takes no options (splitting cannot change semantics), or the "
            "script provably runs only on operator-supplied arguments from a trusted "
            "operator console with no untrusted filenames in scope."
        ),
        "vuln": "rm -rf $UNQUOTED_DIR_PATH",
        "safe": "rm -rf -- \"$UNQUOTED_DIR_PATH\"",
        "signal": r"rm\s+-rf\s+\$UNQUOTED_DIR_PATH",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "Bash Reference Manual: Word Splitting — https://www.gnu.org/software/bash/manual/html_node/Word-Splitting.html",
            "Bash Reference Manual: Shell Parameter Expansion — https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html",
            "POSIX Shell Command Language §2.6 Word Expansions — https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html",
        ],
        "doc_url": "https://www.gnu.org/software/bash/manual/html_node/Word-Splitting.html",
    },
    {
        "num": "02",
        "title": "Code Injection in eval and Command Substitution",
        "platform": "POSIX sh and bash on Linux/macOS; BASH_ENV/ENV startup-file behavior is bash/sh-specific and does not apply to scripts run with the -p (privileged) setuid path",
        "mechanism": (
            "eval concatenates its arguments and hands the string back through the "
            "full grammar a second time, so any quoting that survived the first parse "
            "is re-interpreted: a semicolon, pipe, backtick or $(...) inside the "
            "input becomes shell syntax, not text. The same re-parse happens in "
            "indirect expansion ${!var} (the named variable's own expansion is "
            "evaluated), in arithmetic contexts where $((expr)) expands variable "
            "names recursively, and in trap 'string' which is evaluated as code when "
            "the signal fires. Piping fetched content straight to an interpreter "
            "(curl ... | sh, eval \"$(curl ...)\") collapses transport integrity and "
            "execution into one step with no review point in between."
        ),
        "source": (
            "Text the script does not author: configuration values sourced from "
            "untrusted files, user replies from read, remote installer payloads "
            "fetched over the network, environment variables in a CI runner, or "
            "variable names supplied externally to ${!var} and declare."
        ),
        "sink": (
            "eval of dynamic strings; sh -c \"$x\"; source/. of externally chosen "
            "paths; ${!var} with an externally influenced name; arithmetic evaluation "
            "of input-derived expressions; trap \"...$var...\"; curl|sh and "
            "eval \"$(curl ...)\" pipelines"
        ),
        "guards": (
            "Check the executed string is built from server-side constants only; check "
            "dynamic dispatch is replaced by a case allowlist instead of eval or "
            "${!var}; check fetched content is written to a file, integrity-verified "
            "(checksum/signature), read, and only then executed; check trap bodies "
            "contain no variable interpolation; check arithmetic uses a validated "
            "numeric variable, not raw input text."
        ),
        "not_candidate_when": (
            "eval executes only literal constant strings (e.g. eval \"$setflags\" "
            "where setflags is defined verbatim in the script), the indirect name "
            "comes from a fixed internal set validated against ^[A-Za-z_][A-Za-z0-9_]*$, "
            "or the fetched payload is pinned by a cryptographic checksum verified "
            "before execution with no network path around the check."
        ),
        "vuln": "eval \"$user_cmd_input\"",
        "safe": "run_fixed_command \"$user_cmd_input\"",
        "signal": r"eval\s+\"\$user_cmd_input\"",
        "references": [
            "CWE-95: Eval Injection — https://cwe.mitre.org/data/definitions/95.html",
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "Bash Reference Manual: Quoting — https://www.gnu.org/software/bash/manual/html_node/Quoting.html",
            "Bash Reference Manual: Bash Startup Files — https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html",
        ],
        "doc_url": "https://www.gnu.org/software/bash/manual/html_node/Quoting.html",
    },
    {
        "num": "03",
        "title": "Option Injection via Unfiltered Flags",
        "platform": "POSIX sh and bash on Linux/macOS; '--' end-of-options convention follows the POSIX Utility Syntax Guidelines, which not every third-party utility implements",
        "mechanism": (
            "Most POSIX utilities parse an operand that begins with '-' as an option, "
            "so an attacker who controls a filename or argument can turn data into "
            "flags: a file named '-n' or '--output' passed unguarded to cat, sort or "
            "cp changes the invoked behavior instead of being read. Without '--', "
            "there is no syntax boundary between the option region and operands, and "
            "utilities that do support '--' still differ on which options consume the "
            "next word. Glob expansion has the same shape: a pattern supplied by the "
            "user that matches nothing stays literal (nullglob off), and xargs "
            "without -0 splits its input on quotes and whitespace, letting a crafted "
            "filename inject entirely new arguments."
        ),
        "source": (
            "Untrusted filenames (uploads, archive members, directory listings of "
            "shared paths), user-chosen argument values in wrappers, and output of "
            "tools piped into xargs."
        ),
        "sink": (
            "Utility invocations where an input-derived value follows the command "
            "name with no '--' separator: cat/sort/head/cp/mv/kill, tar with "
            "input-derived flags, xargs without -0 or -d, git/curl wrapper scripts "
            "forwarding user arguments"
        ),
        "guards": (
            "Check a literal '--' precedes every input-derived operand; check xargs "
            "uses -0 (with find -print0 / sort -z) or -d '\\n'; check input-derived "
            "values are prefixed or validated to reject a leading '-' (case $arg in "
            "-*) reject); check glob results are iterated with quoted \"$@\" so each "
            "match is one operand."
        ),
        "not_candidate_when": (
            "The operand is validated against a grammar that cannot start with '-' "
            "(numeric IDs, absolute paths built server-side), '--' is already present "
            "before the operand and the target utility implements it, or xargs -0 "
            "pairs with NUL-delimited producers so injection through quoting is "
            "impossible."
        ),
        "vuln": "cat $user_file_param",
        "safe": "cat -- \"$user_file_param\"",
        "signal": r"cat\s+\$user_file_param",
        "references": [
            "CWE-88: Argument Injection or Modification — https://cwe.mitre.org/data/definitions/88.html",
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "POSIX Utility Syntax Guidelines — https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html",
        ],
        "doc_url": "https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html",
    },
    {
        "num": "04",
        "title": "Predictable Temporary Files in /tmp",
        "platform": "POSIX sh and bash on Linux/macOS; mktemp is available in GNU coreutils, busybox, and macOS, but the legacy mktemp(3) C-call pattern and /tmp/PID naming persist in older install scripts",
        "mechanism": (
            "A name built as /tmp/name.$$ is fully predictable: the PID is visible to "
            "other processes through /proc or ps, so a local attacker creates the path "
            "first — as a symlink pointing at a sensitive file, or as a file they "
            "hold open — and the privileged script's subsequent redirection writes "
            "through the symlink or into attacker-readable state. The check-then-use "
            "idiom ([ -f $f ] before writing) does not close the window: the check "
            "and the open are separate system calls and the attacker swaps the path "
            "between them. mktemp closes this because it creates the file atomically "
            "with O_EXCL on a randomized name and prints only the name it owns."
        ),
        "source": (
            "Local attacker visibility in multi-user /tmp, shared CI workspaces, and "
            "setuid or root-run install scripts whose PID and filename layout are "
            "observable."
        ),
        "sink": (
            "Redirection or writes to /tmp paths built from $$, fixed names, or "
            "user-influenced components; mktemp invoked with a template lacking "
            "X's or on a path the attacker can pre-create; any [ -f ]/[ -e ] test "
            "followed by a separate open/write of the same path in a privileged script"
        ),
        "guards": (
            "Check temporary files are created only via mktemp (template with at "
            "least three trailing X's) inside a directory the script controls, or "
            "via mktemp -d for multi-file work; check no user-influenced component "
            "enters the temp path; check privileged scripts never write into a "
            "world-writable directory by predictable name and avoid test-then-write "
            "idioms."
        ),
        "not_candidate_when": (
            "The temporary name comes from mktemp/TEMPDIR created at runtime with "
            "O_EXCL semantics, the script writes inside a private directory (0700 "
            "runtime dir, mktemp -d) instead of /tmp, or the target system is "
            "single-user with no untrusted local accounts able to pre-create paths."
        ),
        "vuln": "tmpfile=\"/tmp/test.$$\"; echo data > \"$tmpfile\"",
        "safe": "tmpfile=\"$(mktemp /tmp/test.XXXXXX)\"; echo data > \"$tmpfile\"",
        "signal": r"tmpfile=\"/tmp/test\.\$\$\"",
        "references": [
            "CWE-377: Insecure Temporary File — https://cwe.mitre.org/data/definitions/377.html",
            "CWE-59: Improper Link Resolution Before File Access — https://cwe.mitre.org/data/definitions/59.html",
            "POSIX mktemp utility specification — https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html",
        ],
        "doc_url": "https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html",
    },
    {
        "num": "05",
        "title": "Insecure PATH Inheritance and Environment Trust",
        "platform": "POSIX sh and bash on Linux/macOS; bash skips BASH_ENV and sourced functions under setuid invocation, but root shell contexts without -p still honor inherited PATH, IFS and exported functions",
        "mechanism": (
            "An unqualified command name is resolved by walking $PATH left to right at "
            "call time, so in a privileged context an attacker-controlled PATH entry "
            "placed first supplies a substitute executable that runs with the "
            "script's privileges. The same trust surface includes IFS (inherited "
            "through some older shells' environments, changing every unquoted "
            "expansion), BASH_ENV/ENV (pointing bash/sh at an attacker-writable "
            "startup file that executes before the script body), LD_PRELOAD and "
            "_dyld_* variables, and exported function definitions, which a child "
            "bash imports and can therefore replace a utility's behavior wholesale."
        ),
        "source": (
            "Environment inherited from an untrusted caller: setuid or sudo-invoked "
            "scripts, CI runners triggered by untrusted pull requests, cron/systemd "
            "jobs whose environment an attacker can influence, and any wrapper "
            "invoked with env or a user-modified PATH."
        ),
        "sink": (
            "Unqualified command names (tar, grep, awk, helper scripts) executed in "
            "a privileged script without a pinned PATH; scripts that read BASH_ENV/"
            "ENV-honored startup files; shells started with inherited exported "
            "functions; use of IFS from the environment"
        ),
        "guards": (
            "Check the script pins PATH to a fixed list of root-owned directories at "
            "the top (PATH=/usr/bin:/bin; export PATH) and invokes security-critical "
            "binaries by absolute path; check setuid scripts use setpriv/env -i or "
            "bash -p so inherited env is dropped; check IFS is reset explicitly "
            "(IFS=$' \\t\\n'); check exported functions are unset (-f) before "
            "privilege-sensitive work."
        ),
        "not_candidate_when": (
            "PATH is pinned to a constant, root-owned list before the first command "
            "and security-relevant binaries are called by absolute path, the script "
            "only ever runs from a trusted operator environment (interactive root "
            "shell, locked-down CI image) where no untrusted party can set variables, "
            "or the script runs under env -i / bash -p so the inherited environment "
            "is empty by construction."
        ),
        "vuln": "cleanup_script_unqualified",
        "safe": "/usr/local/bin/cleanup_script_safe",
        "signal": r"cleanup_script_unqualified",
        "references": [
            "CWE-426: Untrusted Search Path — https://cwe.mitre.org/data/definitions/426.html",
            "CWE-427: Uncontrolled Search Path Element — https://cwe.mitre.org/data/definitions/427.html",
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "Bash Reference Manual: Bash Variables (PATH, BASH_ENV, PS4) — https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html",
        ],
        "doc_url": "https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html",
    },
    {
        "num": "06",
        "title": "Fail-Open Execution without set -euo pipefail",
        "platform": "POSIX sh supports set -e/-u but NOT pipefail; set -o pipefail requires bash, ksh or zsh; 'local x=$(cmd)' masking exit status is a bash/ksh behavior",
        "mechanism": (
            "Without set -e the shell keeps executing after any failure, so a failed "
            "signature or checksum verification (gpg verify, sha256sum -c) prints an "
            "error and the next line installs or runs the unverified artifact anyway. "
            "In a pipeline the exit status comes from the last command by default, "
            "so 'curl ... | sh' succeeds even when the download failed or was "
            "tampered mid-stream; pipefail exists to surface this and is POSIX-only "
            "in the non-portable direction. Two quiet paths add to it: 'local "
            "x=$(cmd)' discards the substitution's exit status because 'local' "
            "succeeds, and 'cmd || true' converts any failure — including a failed "
            "permission change — into success."
        ),
        "source": (
            "Installer and CI steps whose inputs are fetched or attacker-influenced "
            "(downloaded packages, PR-modified manifests), where a silent failure "
            "advances to the next stage instead of aborting."
        ),
        "sink": (
            "Verification-then-act sequences (checksum/signature check followed by "
            "install, chmod/chown, service start) in scripts lacking set -euo "
            "pipefail at the top, or where '|| true', unguarded cd, or "
            "'local x=$(cmd)' neutralizes a failure on the security-relevant step"
        ),
        "guards": (
            "Check set -euo pipefail is set before any security-relevant command "
            "(with set -o pipefail verified as supported by the interpreter); check "
            "verification commands are chained explicitly (verify && install, or "
            "if ! verify; then exit 1; fi); check cd is followed by an exit-status "
            "test or set -e is active; check no '|| true' on permission, signature, "
            "or checksum steps; check 'local' is split from its assignment when the "
            "exit status matters."
        ),
        "not_candidate_when": (
            "set -euo pipefail is active and verification commands run directly (no "
            "pipeline or || true softening), each security step's status is checked "
            "explicitly with if/&&, or the script's only consumers are non-security "
            "steps whose failure mode is a build error rather than a privilege or "
            "integrity change."
        ),
        "vuln": "sha256sum -c hash.txt; install_package.sh",
        "safe": "set -euo pipefail; sha256sum -c hash.txt; install_package.sh",
        "signal": r"sha256sum\s+-c\s+hash\.txt;\s*install_package\.sh",
        "references": [
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "CWE-252: Unchecked Return Value — https://cwe.mitre.org/data/definitions/252.html",
            "CWE-347: Improper Verification of Cryptographic Signature — https://cwe.mitre.org/data/definitions/347.html",
            "POSIX Shell Command Language §2 (exit status and set -e) — https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html",
        ],
        "doc_url": "https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html",
    },
    {
        "num": "07",
        "title": "Variable Scope, Attributes, and Name Reference Pollution",
        "platform": "bash 4.3+ for declare -n namerefs; printf -v, declare, and export -f are bash/ksh features not present in POSIX sh; readonly assumptions differ across bash versions",
        "mechanism": (
            "Inside a function, an assignment to an undeclared name writes the global "
            "scope, so two concurrent invocations of a helper that sets 'status' or "
            "'user' without local overwrite each other's security-relevant state. "
            "Worse, several builtins take the variable NAME as data: declare -n "
            "ref=\"$user_input\" makes ref an alias to whatever variable the external "
            "input names (including readonly or PATH), and declare \"$name=$value\", "
            "printf -v \"$name\", and read \"$name\" perform an assignment whose left "
            "side is attacker-chosen. export and export -f carry selected names and "
            "even function bodies into every child process, so a helper's internal "
            "state or a whole function implementation escapes the process boundary; "
            "and code that treats a readonly declaration as tamper-proof can be "
            "surprised, since unset/duplicate handling of readonly names differs "
            "across shell versions."
        ),
        "source": (
            "Externally supplied identifier strings (config keys, query or flag names "
            "turned into variable names, environment-derived key names in CI) and "
            "shared-variable names in scripts run concurrently or re-entrant."
        ),
        "sink": (
            "declare -n / local -n with input-derived names; declare \"$name=$value\"; "
            "printf -v \"$name\"; read into input-derived names; assignments to "
            "non-local names inside functions on security paths; export/export -f of "
            "secret-bearing or security-relevant names"
        ),
        "guards": (
            "Check every function-local assignment is declared local; check any "
            "builtin taking a variable name validates it against ^[A-Za-z_][A-Za-z0-9_]*$ "
            "and an allowlist before use; check secrets are passed via files or "
            "fd inheritance rather than export; check no export -f is used near "
            "privilege boundaries."
        ),
        "not_candidate_when": (
            "The name argument is validated against a strict identifier pattern and "
            "an allowlist before reaching declare/printf -v/read, all function "
            "variables are local and the script is single-threaded so no cross-call "
            "state persists, or nothing sensitive is exported and the child "
            "processes are trusted."
        ),
        "vuln": "declare -n ref=\"$user_input\"; ref=\"value\"",
        "safe": "/* strictly validate variable name */",
        "signal": r"declare\s+-n\s+ref=\"\$user_input\"",
        "references": [
            "CWE-621: Variable Extraction — https://cwe.mitre.org/data/definitions/621.html",
            "CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component — https://cwe.mitre.org/data/definitions/74.html",
            "Bash Reference Manual: Shell Parameter Expansion (nameref declarations) — https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html",
        ],
        "doc_url": "https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html",
    },
    {
        "num": "08",
        "title": "Secret Leakage in Process Arguments and set -x",
        "platform": "POSIX sh and bash on Linux/macOS; xtrace (set -x/-v) and PS4 expansion are interpreter-level and apply to any CI or interactive context where trace output is captured to logs",
        "mechanism": (
            "Everything in a command line is world-readable while the process runs: "
            "ps, /proc/<pid>/cmdline, and shell/job accounting all expose argv "
            "verbatim, so a token passed as 'curl -H \"Authorization: $TOKEN\"' is "
            "readable by any local user for the duration of the request. Tracing "
            "leaks the same values statically: set -x prints each expanded command "
            "line (including the token) to stderr, where CI systems capture it into "
            "build logs; PS4 is expanded before printing, and a PS4 containing "
            "$(...) executes and emits further data. export propagates a secret to "
            "every child process and its environment, which outlives the command in "
            "child core dumps and third-party tools; here-docs/here-strings may be "
            "implemented via temporary files on disk."
        ),
        "source": (
            "Credentials the script holds: API tokens, deploy keys, cloud "
            "credentials, password variables passed in from CI secret stores or "
            "operator prompts."
        ),
        "sink": (
            "Secrets interpolated into command arguments (curl -H, wget --header, "
            "client CLI flags), scripts running with set -x/-v or a PS4 containing "
            "command substitution, export of secret variables, and here-doc/"
            "here-string bodies carrying credentials"
        ),
        "guards": (
            "Check secrets reach the target via stdin, a config file read with fd "
            "redirection (curl -K <(...)), or environment variables consumed "
            "in-process rather than argv; check no set -x/-v is active on "
            "credential-handling paths (and set +x precedes them if tracing is "
            "needed); check PS4 contains no $(...) or ${...} expansions; check "
            "secrets are not exported beyond the immediate child."
        ),
        "not_candidate_when": (
            "The secret is passed via stdin or an fd-based config mechanism that "
            "never appears in argv, tracing is disabled and PS4 is a literal "
            "constant on all credential paths, or the value in argv is a "
            "short-lived, low-privilege identifier rather than a credential "
            "(e.g. a public URL or a ticket number)."
        ),
        "vuln": "curl -H \"Authorization: $TOKEN\" http://example.com",
        "safe": "curl -K <(echo \"header = \\\"Authorization: $TOKEN\\\"\") http://example.com",
        "signal": r"curl\s+-H\s+\"Authorization:\s+\$TOKEN\"",
        "references": [
            "CWE-214: Invocation of Process Using Visible Sensitive Information — https://cwe.mitre.org/data/definitions/214.html",
            "CWE-532: Insertion of Sensitive Information into Log File — https://cwe.mitre.org/data/definitions/532.html",
            "CWE-312: Cleartext Storage of Sensitive Information — https://cwe.mitre.org/data/definitions/312.html",
            "Bash Reference Manual: Bash Variables (PS4) — https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html",
        ],
        "doc_url": "https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html",
    },
    {
        "num": "09",
        "title": "Destructive File Operations on Empty Variables",
        "platform": "POSIX sh and bash on Linux/macOS; ${var:?} expansion and symlink-following chown -h/-P behavior are portable, glob-matches-nothing semantics default to leaving the pattern literal",
        "mechanism": (
            "If DIR is unset or empty, 'rm -rf \"$DIR/\"*' concatenates to 'rm -rf \"/\"*' "
            "and the glob expands to the filesystem root: the script deletes the "
            "system with root's privileges. Empty-variable expansion also flattens "
            "intended boundaries in mv/cp/chmod targets, and tar/unzip extraction of "
            "attacker-supplied archives writes outside the target through absolute "
            "or '..' member names. Recursive chown/chmod follow symlinks unless the "
            "implementation's -P/-h semantics are used, letting a planted symlink "
            "move the operation onto /etc or another critical path; and a loop over "
            "unquoted find/ls output breaks on filenames containing newlines, so one "
            "crafted name causes two operands where the script expected one."
        ),
        "source": (
            "Configuration or environment variables holding destination paths that "
            "an untrusted party can leave unset or empty; archive member names from "
            "untrusted archives; filenames in shared directories (including names "
            "containing newlines or crafted symlinks)."
        ),
        "sink": (
            "rm -rf, mv, cp, chmod -R, chown -R executed on expansions without a "
            "non-empty assertion; tar/unzip extraction of untrusted archives without "
            "member validation; recursive permission operations over directories "
            "containing attacker-planted symlinks; unquoted for-loops over filenames"
        ),
        "guards": (
            "Check every destructive target uses ${var:?message} so an empty or "
            "unset variable aborts the script; check '--' precedes operands; check "
            "archive extraction validates member paths (no leading '/', no '..') or "
            "extracts into a fresh empty directory with realpath containment "
            "checking; check recursive chown/chmod pass -P/-h (no symlink "
            "following) and loops quote their input (while IFS= read -r)."
        ),
        "not_candidate_when": (
            "The destination variable is asserted non-empty with ${var:?} and "
            "validated against an expected prefix before the destructive command, "
            "the archive is produced by the same trusted pipeline that consumes it "
            "with member names verified, or the operation runs in a container/"
            "scratch namespace where the deleted or re-permissioned tree has no "
            "security value."
        ),
        "vuln": "rm -rf \"$UNCHECKED_DEST/\"*",
        "safe": "rm -rf -- \"${UNCHECKED_DEST:?Destination required}/\"*",
        "signal": r"rm\s+-rf\s+\"\$UNCHECKED_DEST/\"\*",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-59: Improper Link Resolution Before File Access — https://cwe.mitre.org/data/definitions/59.html",
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "Bash Reference Manual: Shell Parameter Expansion (${var:?word}) — https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html",
        ],
        "doc_url": "https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html",
    },
    {
        "num": "10",
        "title": "Secondary Injection into Remote Shells and Utilities",
        "platform": "POSIX sh and bash on Linux/macOS; ssh invokes the remote user's login shell to parse the command string, so quoting semantics on the remote side follow the remote account's shell",
        "mechanism": (
            "A remote command given as one quoted string is parsed twice: the local "
            "shell expands $x first, then ssh hands the resulting string to the "
            "remote user's login shell, which parses it again as shell grammar. A "
            "value containing a space, semicolon, quote or $ therefore changes "
            "meaning between the two parses — an attacker-controlled filename like "
            "'a; rm -rf /' executes on the remote host as a second command. The "
            "same double-parse exists in program-text injection: sed 's/.../$x/' "
            "and awk scripts interpolate input into the program source, an unquoted "
            "here-doc delimiter lets the remote/local body expand $vars, and "
            "concatenating input into SQL, JSON, or python -c payloads re-uses the "
            "host string as target-language syntax."
        ),
        "source": (
            "Values crossing an interpreter boundary: filenames and hostnames fed "
            "into ssh commands, log fields or user text fed into sed/awk programs, "
            "form input concatenated into SQL/JSON bodies, and arguments to "
            "python -c / psql -c style invocations."
        ),
        "sink": (
            "ssh host \"...$var...\"; sed/awk invocations with interpolated program "
            "text; here-docs whose delimiter is unquoted; string concatenation into "
            "SQL statements, JSON payloads, or python -c/- <<EOF script bodies"
        ),
        "guards": (
            "Check values crossing to a remote shell are single-quoted with "
            "printf '%q' (or quoted with ' careful escaping) so the local expansion "
            "produces one literal remote operand; check sed/awk receive data via "
            "-v or ENVIRON/stdin rather than string substitution into the program; "
            "check here-doc delimiters are quoted ('EOF') to suppress expansion; "
            "check SQL/JSON/python -c bodies are built from structured encoders, "
            "not concatenation."
        ),
        "not_candidate_when": (
            "The remote command is a fixed string and no local variable is "
            "interpolated, the interpolated value is passed with printf '%q' "
            "quoting so it arrives as one literal remote operand, the here-doc "
            "delimiter is quoted and the body is constant, or program text for "
            "sed/awk/SQL is constant with data supplied through separate data "
            "channels."
        ),
        "vuln": "ssh remote \"rm -f $filename\"",
        "safe": "ssh remote \"rm -f -- $(printf '%q' \"$filename\")\"",
        "signal": r"ssh\s+remote\s+\"rm\s+-f\s+\$filename\"",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-89: Improper Neutralization of Special Elements in SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "CWE-94: Improper Control of Generation of Code — https://cwe.mitre.org/data/definitions/94.html",
            "Bash Reference Manual: Quoting — https://www.gnu.org/software/bash/manual/html_node/Quoting.html",
            "Bash Reference Manual: Redirections (here-documents) — https://www.gnu.org/software/bash/manual/html_node/Redirections.html",
        ],
        "doc_url": "https://www.gnu.org/software/bash/manual/html_node/Quoting.html",
    },
]
