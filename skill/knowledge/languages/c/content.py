"""Substantive per-card content for the C knowledge cards (c-01..c-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, POSIX/man7 documentation, CERT rule names).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (C section).
"""

LANGUAGE = {
    "name": "C",
    "prefix": "c",
}

CARDS = [
    {
        "num": "01",
        "title": "Out-of-Bounds Memory Access in Buffers",
        "platform": (
            "C99/C11 semantics on any hosted toolchain (glibc, musl, MSVC CRT); "
            "the failure mode is silent corruption whose visibility depends on "
            "compiler optimization level and heap layout"
        ),
        "mechanism": (
            "C array semantics carry no bounds metadata: a length or index arrives "
            "as a plain integer and strcpy/memcpy/sprintf trust the caller's count, "
            "so an attacker-supplied source string or length writes past the "
            "destination object. The write lands in adjacent stack or heap memory, "
            "overwriting saved return addresses, function pointers, or neighbouring "
            "heap metadata, and is only detected if a canary/ASLR/fortify combination "
            "happens to intercept it. The standard classifies the access as undefined "
            "behavior, so the optimizer may also delete subsequent bounds checks "
            "based on the assumption that no out-of-bounds access occurs."
        ),
        "source": (
            "Any length, count, or string that crosses a trust boundary: network "
            "protocol fields and headers, file content, environment variables, argv, "
            "or device/IPC buffers."
        ),
        "sink": (
            "strcpy/sprintf/strcat with a fixed-size destination; memcpy/memmove with "
            "an attacker-derived n; array indexing a[i] where i is unchecked input"
        ),
        "guards": (
            "Check that the copy length is clamped to sizeof(dst) before the call "
            "(or that a strlcpy/snprintf equivalent is used), that the source length "
            "is known rather than assumed, and that indices are validated against the "
            "declared bound before every indexing operation on the affected path."
        ),
        "not_candidate_when": (
            "The length and buffer are compile-time constants with the copy provably "
            "in-bounds (e.g. memcpy of a fixed-size constant record), the input is a "
            "length-validated protocol field whose bound is enforced before the copy, "
            "or the code path is only reachable with data generated inside the same "
            "trust domain (no network, file, or IPC attacker control)."
        ),
        "vuln": "strcpy(dest, untrusted_src);",
        "safe": "strncpy(dest, untrusted_src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\\0';",
        "signal": r"strcpy\(",
        "references": [
            "CWE-120: Buffer Copy without Checking Size of Input — https://cwe.mitre.org/data/definitions/120.html",
            "CWE-787: Out-of-bounds Write — https://cwe.mitre.org/data/definitions/787.html",
            "CWE-125: Out-of-bounds Read — https://cwe.mitre.org/data/definitions/125.html",
            "SEI CERT C Coding Standard: ARR38-C (pointer/array bounds)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/120.html",
    },
    {
        "num": "02",
        "title": "Integer Overflow and Truncation in Allocation",
        "platform": (
            "C99/C11 on any hosted toolchain; signed overflow is undefined behavior "
            "(optimizers may remove the guard), unsigned overflow wraps silently"
        ),
        "mechanism": (
            "Allocation sizes are computed in machine integers before malloc sees "
            "them: `count * elem_size` on a 32-bit or 64-bit width wraps modulo 2^N, "
            "so two large attacker-supplied values multiply to a small total and the "
            "allocation succeeds with a fraction of the needed storage. Later writes "
            "indexed by the original count then run off the end of the small block. "
            "Mixing signed int with size_t truncates or sign-extends: a negative int "
            "converted to size_t becomes a huge unsigned value, and a value above "
            "INT_MAX reinterpreted after a check written for int passes a check the "
            "allocator never applies. Because signed overflow is undefined behavior, "
            "a check written after the multiplication can also be optimized away."
        ),
        "source": (
            "Counts, element sizes, or lengths taken from protocol fields, file "
            "headers, or array/loop parameters that the client controls (e.g. a "
            "number-of-items field followed by that many elements)."
        ),
        "sink": (
            "malloc/calloc/realloc/alalloca called with a computed size; loop bounds "
            "and memcpy sizes derived from the same product"
        ),
        "guards": (
            "Check that the multiplication uses a checked primitive "
            "(__builtin_mul_overflow, __builtin_add_overflow, or CERT-recommended "
            "pre-division check like `if (elem_size && count > SIZE_MAX / elem_size)`), "
            "that the result is held in size_t end to end, and that the count is "
            "bounded by an explicit protocol maximum before arithmetic."
        ),
        "not_candidate_when": (
            "The count is validated against a fixed protocol maximum well below the "
            "overflow threshold before any arithmetic, the element size is a "
            "compile-time constant and the count is already bounded, or the allocation "
            "feeds an internal batch job whose inputs no external party controls."
        ),
        "vuln": "size_t total = count * elem_size; void *p = malloc(total);",
        "safe": "if (__builtin_mul_overflow(count, elem_size, &total)) return -1; void *p = malloc(total);",
        "signal": r"malloc\(total\)",
        "references": [
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-128: Wrap-around Error — https://cwe.mitre.org/data/definitions/128.html",
            "CWE-197: Numeric Truncation Error — https://cwe.mitre.org/data/definitions/197.html",
            "SEI CERT C Coding Standard: INT30-C (unsigned overflow), MEM35-C (allocation size check)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/190.html",
    },
    {
        "num": "03",
        "title": "Use-After-Free and Double-Free in Cleanup Paths",
        "platform": (
            "C99/C11 on any hosted toolchain with a malloc/free allocator (glibc, "
            "musl, MSVC CRT); exploitation difficulty depends on allocator hardening"
        ),
        "mechanism": (
            "Ownership in C is purely conventional: free() unlinks the block and "
            "returns immediately, leaving the pointer variable holding the old "
            "address. Error paths that free the same pointer on two exits (goto "
            "cleanup without nulling, or a second free inside an if(err) block) hand "
            "the allocator a stale chunk: a use reads whatever the allocator wrote "
            "into the freed header, and a double free corrupts the free list into "
            "returning overlapping allocations. Callback registrations and retry "
            "paths extend the lifetime gap: a consumer holding the pointer runs "
            "after the owner already released it."
        ),
        "source": (
            "Any path that changes control flow after ownership transfers: error "
            "returns, signal interruption, disconnect/retry handling, callbacks "
            "invoked from another subsystem holding a borrowed pointer."
        ),
        "sink": (
            "free() reached twice for one pointer; dereference or memcpy through a "
            "pointer after its free call; re-assignment of a freed pointer into a "
            "still-live structure"
        ),
        "guards": (
            "Check that every free site sets the pointer to NULL immediately after "
            "(free(p); p = NULL;), that cleanup labels are idempotent (each free "
            "guarded by a NULL test or reached on exactly one path), and that "
            "callbacks/registrations are unregistered before the owner frees the "
            "shared object."
        ),
        "not_candidate_when": (
            "The pointer is set to NULL at every free site so a second free is "
            "provably free(NULL), the object's lifetime provably ends with the "
            "request and no alias survives it, or the cleanup path is unreachable "
            "because the failure it handles cannot occur on the audited path."
        ),
        "vuln": "free(ptr); if (err) { free(ptr); return; }",
        "safe": "free(ptr); ptr = NULL; if (err) return;",
        "signal": r"free\(ptr\)",
        "references": [
            "CWE-416: Use After Free — https://cwe.mitre.org/data/definitions/416.html",
            "CWE-415: Double Free — https://cwe.mitre.org/data/definitions/415.html",
            "SEI CERT C Coding Standard: MEM30-C (no access to freed memory), MEM32-C (detect heap corruption)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/416.html",
    },
    {
        "num": "04",
        "title": "Uninitialized Memory Usage and Information Leakage",
        "platform": (
            "C99/C11 on any hosted toolchain; padding-byte exposure depends on the "
            "platform ABI's struct alignment rules"
        ),
        "mechanism": (
            "Automatic (stack) variables and malloc'd blocks start as whatever bytes "
            "were already in memory; reading them yields values from a previous "
            "stack frame or freed allocation. Two harms follow: logic computed on "
            "uninitialized fields is attacker-shiftable (a flag or length read as "
            "garbage may pass a check), and serializing a partially initialized "
            "struct — including ABI padding bytes the compiler inserts between "
            "members — copies stale heap or stack contents into output the attacker "
            "receives. Tools see the source-level type, not the padding, so "
            "memcpy(out, &d, sizeof(d)) leaks more than the declared fields."
        ),
        "source": (
            "Short reads and partially-filled buffers (read/recv returning fewer "
            "bytes than requested), error paths that skip initialization, and "
            "response serialization of stack or heap objects."
        ),
        "sink": (
            "memcpy/send/write of an object that was not fully written; use of a "
            "local or malloc'd variable on a path where its initialization call "
            "was skipped or partial"
        ),
        "guards": (
            "Check that stack aggregates are zero-initialized at declaration "
            "(`= {0}` or memset before first use), that malloc'd buffers are "
            "initialized before read or checked against calloc, and that every "
            "short-read path (read/recv return < requested) writes or discards the "
            "unfilled tail before the buffer is used or sent."
        ),
        "not_candidate_when": (
            "The object is fully initialized on every path reaching the use "
            "(including the error path), the buffer is only consumed internally and "
            "never serialized or compared, or the copied region excludes padding "
            "and uninitialized members by construction (field-by-field copy)."
        ),
        "vuln": "struct Data d; memcpy(out, &d, sizeof(d));",
        "safe": "struct Data d = {0}; memcpy(out, &d, sizeof(d));",
        "signal": r"struct\s+Data\s+d;",
        "references": [
            "CWE-457: Use of Uninitialized Variable — https://cwe.mitre.org/data/definitions/457.html",
            "CWE-908: Use of Uninitialized Resource — https://cwe.mitre.org/data/definitions/908.html",
            "SEI CERT C Coding Standard: EXP33-C (no reads of uninitialized memory), MSC04-C (padding leaks)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/457.html",
    },
    {
        "num": "05",
        "title": "Format String Vulnerability in Output APIs",
        "platform": (
            "C99/C11 on any hosted toolchain; %n exploitation depends on writable-"
            "memory protections (RELRO, W^X) of the linked libc"
        ),
        "mechanism": (
            "The printf family takes the format string as an interpreter program: "
            "each conversion spec reads its argument from the varargs stack by "
            "position, and the callee has no way to know how many arguments were "
            "actually passed. When the format string is attacker-controlled, %x/%p "
            "walk past the real arguments and dump stack memory (%-leak), while %n "
            "writes the number of emitted bytes so far to the address found on the "
            "stack, converting a log or echo line into an arbitrary write primitive. "
            "syslog(LOG_INFO, user_input) has the same defect because syslog formats "
            "its message argument."
        ),
        "source": (
            "Any string printed, logged, or echoed: request paths and user agents "
            "fed into printf, argv echoed back, protocol identifiers passed to "
            "syslog or snprintf as the format argument."
        ),
        "sink": (
            "printf/fprintf/snprintf/sprintf/syslog/err* called with a non-literal "
            "first (format) argument that carries attacker influence"
        ),
        "guards": (
            "Check that every call passes a compile-time literal format "
            "(printf(\"%s\", input)), that -Wformat-security / -Wformat=2 is enabled "
            "so non-literal formats fail the build, and that any dynamic-template "
            "need is met by a fixed-format construction rather than concatenation."
        ),
        "not_candidate_when": (
            "The format argument is a compile-time string literal, the non-literal "
            "string is provably built from constants with no attacker influence, or "
            "the call is on a build/configuration path (compiler-internal tooling) "
            "that never receives external input."
        ),
        "vuln": "printf(user_supplied_str);",
        "safe": "printf(\"%s\", user_supplied_str);",
        "signal": r"printf\([a-zA-Z_]",
        "references": [
            "CWE-134: Use of Externally-Controlled Format String — https://cwe.mitre.org/data/definitions/134.html",
            "man7.org: printf(3) — https://man7.org/linux/man-pages/man3/printf.3.html",
            "SEI CERT C Coding Standard: FIO30-C (exclude user input from format strings)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/134.html",
    },
    {
        "num": "06",
        "title": "String Termination and Off-by-One Errors",
        "platform": (
            "C99/C11 on any hosted toolchain; consequences depend on how the "
            "surrounding code consumes non-NUL-terminated buffers"
        ),
        "mechanism": (
            "strncpy copies at most n bytes and pads with NUL bytes only if the "
            "source is shorter; when strlen(src) >= n it copies exactly n bytes and "
            "writes no terminator, leaving dst an unterminated char array. A later "
            "strlen/printf/strcpy on dst runs off the end into adjacent memory — "
            "both an overread (leaking whatever follows, e.g. a secret in a "
            "neighbouring buffer) and an overread-driven overflow when a copy is "
            "made from it. The same arithmetic produces off-by-one conditions: "
            "buffers sized len instead of len+1, loops that write buf[len] as the "
            "terminator into an array declared [len]."
        ),
        "source": (
            "Strings whose length the attacker controls: usernames, paths, header "
            "values, protocol strings that reach a fixed-size copy and are later "
            "treated as C strings."
        ),
        "sink": (
            "strncpy into a fixed buffer followed by strlen/printf/strcpy on that "
            "buffer; any strlen on a buffer that is not provably NUL-terminated"
        ),
        "guards": (
            "Check that the byte after a strncpy result is explicitly NUL-written "
            "(dst[sizeof(dst)-1] = '\\0'), that truncation itself is detected "
            "(source length compared before copy), or that snprintf with sizeof(dst) "
            "replaces the strncpy; verify no strlen/read is applied to a buffer "
            "whose termination depends on the copy."
        ),
        "not_candidate_when": (
            "The buffer is explicitly terminated after every strncpy on all paths, "
            "the source is bounded by a length check that guarantees room for the "
            "terminator, or the copied region is used with explicit lengths only "
            "(never as a C string)."
        ),
        "vuln": "strncpy(buf, src, sizeof(buf));",
        "safe": "snprintf(buf, sizeof(buf), \"%s\", src);",
        "signal": r"strncpy\(",
        "references": [
            "CWE-170: Improper Null Termination — https://cwe.mitre.org/data/definitions/170.html",
            "CWE-193: Off-by-one Error — https://cwe.mitre.org/data/definitions/193.html",
            "CWE-125: Out-of-bounds Read — https://cwe.mitre.org/data/definitions/125.html",
            "SEI CERT C Coding Standard: STR32-C (null-terminate byte strings), STR31-C (bounds before string ops)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/170.html",
    },
    {
        "num": "07",
        "title": "Error Path and Return Value Dropping Causing Fail-Open",
        "platform": (
            "C99/C11 on any hosted toolchain; C has no exceptions, so every failure "
            "is signalled only through return values, errno, or out-parameters"
        ),
        "mechanism": (
            "Every security-relevant libc call communicates failure through its "
            "return value: malloc returns NULL, read/recv return short counts or -1 "
            "with EINTR/EAGAIN, and custom validators return a status code. C's "
            "calling convention lets the result be discarded silently — a statement "
            "expression `verify_signature(cert);` compiles with no diagnostic, so "
            "the code proceeds exactly as if the check had passed. Partial reads "
            "compound this: a loop that ignores the return of read() processes "
            "whatever garbage remained in the buffer, and cleanup jumps that skip "
            "rollback on error leave the resource in the privileged state the "
            "failure was supposed to undo."
        ),
        "source": (
            "Environment and input conditions that trigger the error path: malformed "
            "certificates, exhausted memory under request load, signals and EINTR "
            "during IO, packets cut short mid-protocol."
        ),
        "sink": (
            "Security validators and fallible resource calls whose return value is "
            "not branched on: verify/authenticate helpers, malloc/read/recv/setuid/"
            "seteuid/chmod on privilege-relevant paths"
        ),
        "guards": (
            "Check that the return of every security decision function is assigned "
            "and branched on with a fail-closed default (deny on error), that "
            "read/recv results are checked for both -1 and short counts before the "
            "buffer is trusted, and that setuid/chmod/malloc failures abort the "
            "privileged operation instead of continuing."
        ),
        "not_candidate_when": (
            "The return value is consumed and every failure branch exits before any "
            "privileged or trust-dependent action, the call cannot fail on the "
            "audited path (documented always-success with an assertion enforced at "
            "startup), or the dropped result is a non-security diagnostic on a path "
            "with no authorization or resource consequence."
        ),
        "vuln": "verify_signature(cert); proceed_action();",
        "safe": "if (!verify_signature(cert)) return -1; proceed_action();",
        "signal": r"verify_signature\(cert\);",
        "references": [
            "CWE-252: Unchecked Return Value — https://cwe.mitre.org/data/definitions/252.html",
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "CWE-755: Improper Handling of Exceptional Conditions — https://cwe.mitre.org/data/definitions/755.html",
            "SEI CERT C Coding Standard: EXP12-C (do not ignore values returned by security functions)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/252.html",
    },
    {
        "num": "08",
        "title": "File System Race Conditions and Insecure Temp Files",
        "platform": (
            "POSIX filesystem semantics (Linux, macOS, other Unix); on Windows the "
            "same class appears via share modes rather than symlink races"
        ),
        "mechanism": (
            "access() answers a question about the path, and open() acts on whatever "
            "object the path names at a later instant: between the two calls an "
            "attacker who can write the directory replaces the file with a symlink, "
            "so the privilege decision made by access() is applied to an object the "
            "attacker chose (TOCTOU). mktemp-style name construction makes the "
            "target predictable, letting the attacker pre-create it or win the race "
            "routinely rather than occasionally. Opening without O_EXCL and "
            "following symlinks by default converts the race into arbitrary file "
            "creation, truncation, or disclosure in privileged directories."
        ),
        "source": (
            "Directories an attacker can write (world-writable temp dirs, spool and "
            "upload paths) and file names arriving from requests that are re-checked "
            "and later reopened."
        ),
        "sink": (
            "access/stat followed by open/fopen on the same path; mktemp/tempnam/"
            "tmpnam; open without O_EXCL|O_NOFOLLOW on attacker-writable directories"
        ),
        "guards": (
            "Check that privileged code opens with O_CREAT|O_EXCL (and O_NOFOLLOW "
            "where the name may be attacker-planted), that no access()/stat() check "
            "gates a later open of the same path (act on the fd instead: fstat, "
            "fchmod, fchown), and that temp files come from mkstemp with 0600 mode."
        ),
        "not_candidate_when": (
            "The file lives in a directory only the process user can write (0700), "
            "the check-and-use pair operates on an already-open fd rather than a "
            "re-resolved path, or names come from mkstemp/O_EXCL so the race cannot "
            "be won by pre-creation."
        ),
        "vuln": "if (access(f, W_OK) == 0) fd = open(f, O_WRONLY);",
        "safe": "fd = open(f, O_WRONLY | O_CREAT | O_EXCL, 0600);",
        "signal": r"access\(.*W_OK\)",
        "references": [
            "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition — https://cwe.mitre.org/data/definitions/367.html",
            "CWE-377: Insecure Temporary File — https://cwe.mitre.org/data/definitions/377.html",
            "CWE-59: Improper Link Resolution Before File Access — https://cwe.mitre.org/data/definitions/59.html",
            "man7.org: open(2) — https://man7.org/linux/man-pages/man2/open.2.html",
            "SEI CERT C Coding Standard: FIO01-C (identify files via fd), POS30-C (mktemp)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/367.html",
    },
    {
        "num": "09",
        "title": "Command Execution and Environment Trust",
        "platform": (
            "POSIX process semantics (fork/exec, /bin/sh via system/popen); PATH "
            "resolution and env inheritance are Unix-specific behaviors"
        ),
        "mechanism": (
            "system() and popen() hand the string to /bin/sh -c, so shell syntax in "
            "the input starts additional commands. exec-family calls avoid the "
            "shell but inherit two trust channels from their caller: PATH lookup — "
            "execvp/execvp-style calls resolve a bare command name against the "
            "current PATH, which a less-privileged child or the invoking user may "
            "have re-pointed — and the environment block, whose LD_PRELOAD/IFS "
            "values the spawned program may honor. Privilege-drop ordering is the "
            "third channel: if the code execs or opens files before dropping "
            "privileges (or drops only the effective uid while the saved uid "
            "remains root), the child inherits privileges the input may steer."
        ),
        "source": (
            "Request or protocol data that reaches the command string or argv, plus "
            "the inherited process environment when the caller runs privileged."
        ),
        "sink": (
            "system()/popen() with any interpolated content; execv/execl/execvp with "
            "attacker-influenced argv or before privilege cleanup"
        ),
        "guards": (
            "Prefer execve with an absolute executable path and a constructed argv "
            "over system(); check that the environment passed to exec is sanitized "
            "(fixed minimal envp) when dropping privileges, that privilege "
            "irreversibly drops (setuid(getuid()) plus saved-id clearing) before "
            "any exec or file open, and that argv elements cannot be interpreted as "
            "options by the target program."
        ),
        "not_candidate_when": (
            "The command string is entirely constant with no external input, argv is "
            "a fixed program path with only allowlisted arguments, or the process "
            "has already dropped all privileges and the child cannot influence "
            "anything the parent trusts."
        ),
        "vuln": "system(user_command);",
        "safe": "execve(\"/bin/trusted\", argv, envp);",
        "signal": r"system\(user_command\)",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-426: Untrusted Search Path — https://cwe.mitre.org/data/definitions/426.html",
            "man7.org: system(3) — https://man7.org/linux/man-pages/man3/system.3.html",
            "SEI CERT C Coding Standard: ENV33-C (no system() when an exec family call suffices), ENV03-C (sanitize environment)",
        ],
        "doc_url": "https://cwe.mitre.org/data/definitions/78.html",
    },
    {
        "num": "10",
        "title": "Undefined Behavior in Concurrency and Signal Safety",
        "platform": (
            "C11 memory model and POSIX signal semantics (Linux, macOS); specific "
            "manifestations depend on compiler optimization and CPU memory ordering"
        ),
        "mechanism": (
            "Signed arithmetic overflow is undefined behavior, so a bounds check "
            "like `if (len + offset < len)` written with signed ints can be "
            "deleted by the optimizer, which assumes the condition cannot be true. "
            "Unsynchronized access to the same object from two threads is a data "
            "race and again undefined behavior: without atomics or a mutex, one "
            "thread's write may become visible torn, reordered, or never — so a "
            "credentials or configuration flag checked without synchronization can "
            "appear set in one thread while another still observes it unset. "
            "Signal handlers add reentrancy: the handler runs on the same thread "
            "at an arbitrary point, so calling malloc/printf (non-async-signal-"
            "safe, both take internal locks) can deadlock or corrupt the heap when "
            "the signal arrives mid-allocation."
        ),
        "source": (
            "Attacker-controlled magnitudes that overflow signed arithmetic on "
            "validation paths, concurrent requests hitting shared state, and "
            "signals an adversary can trigger (SIGSEGV via malformed input, timers, "
            "SIGINT on exposed service processes)."
        ),
        "sink": (
            "Signed overflow arithmetic guarding security checks; reads/writes of "
            "shared flags or pointers without atomics or locks; printf/malloc/"
            "memcpy and other non-async-signal-safe calls inside signal handlers"
        ),
        "guards": (
            "Check that overflow-sensitive bounds arithmetic uses unsigned types or "
            "checked builtins (__builtin_add_overflow) before the comparison, that "
            "shared security state is _Atomic or mutex-protected, and that signal "
            "handlers restrict themselves to volatile sig_atomic_t flags or write() "
            "on a self-pipe."
        ),
        "not_candidate_when": (
            "The arithmetic is unsigned with wrapping treated explicitly, the shared "
            "state is confined to one thread or already synchronized, the handler "
            "only sets a sig_atomic_t flag, or the concurrency is unreachable from "
            "request paths (single-threaded build, init-only state)."
        ),
        "vuln": "void handler(int sig) { printf(\"Signal: %d\\n\", sig); }",
        "safe": "void handler(int sig) { write(STDERR_FILENO, \"sig\\n\", 4); }",
        "signal": r"printf\(\"Signal",
        "references": [
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization — https://cwe.mitre.org/data/definitions/362.html",
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-479: Signal Handler Use of a Non-reentrant Function — https://cwe.mitre.org/data/definitions/479.html",
            "man7.org: signal-safety(7) — https://man7.org/linux/man-pages/man7/signal-safety.7.html",
            "SEI CERT C Coding Standard: SIG30-C (async-signal-safe handlers), MSC21-C (UB in checks)",
        ],
        "doc_url": "https://man7.org/linux/man-pages/man7/signal-safety.7.html",
    },
]
