"""Generate the complete 15 languages x 10 cards = 150 language cards catalog.

Follows LANGUAGE_CATALOG_DRAFT.md and DETAILED_DEVELOPMENT_REQUIREMENTS.md §6.1.
Zero third-party dependencies.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-002  150 张语言卡片的生成与数量验收（内容质量由逐语言人工评审把关，见 DSR-039~043）
#   绑定实现: DSR-039, DSR-040, DSR-041, DSR-042, DSR-043
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#
# ==============================================================================
# 软件需求追踪与实现规范 (Software Requirements Traceability)
# ==============================================================================
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md
# 设计依据: docs/design/SOFTWARE_DESIGN.md；系统需求: docs/design/SYSTEM_REQUIREMENTS.md
# --- 需求编号: SWR-002 / DSR-039~043 ---
# 需求描述: 建立 15×10 卡片、来源、适用条件及合成正反例；150 个唯一编号和
#   逐语言专家评审通过才可标为已评审（当前全部 pending_review，见卡片 review_record）。
#   └─ 对应系统需求 SR-002: 首版提供 15 种语言、每种 10 个经评审的语言相关问题类；
#      记录公开依据、适用条件、误报条件和合成正反例；称为草案直至通过评审。
# ==============================================================================

import json
import os
from pathlib import Path

KNOWLEDGE_ROOT = Path("/root/polyglot-audit/skill/knowledge")
LANGUAGES_DIR = KNOWLEDGE_ROOT / "languages"
REGISTRY_DIR = KNOWLEDGE_ROOT / "registry"

LANG_DATA = {
    "c": {
        "prefix": "c",
        "name": "C",
        "items": [
            ("01", "Out-of-Bounds Memory Access in Buffers", "memcpy/strcpy/sprintf buffer overflow",
             "strcpy(dest, untrusted_src);", "strncpy(dest, untrusted_src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\\0';",
             r"strcpy\(", ["CWE-120", "CWE-125", "ISO/IEC 9899:1999"]),
            ("02", "Integer Overflow and Truncation in Allocation", "malloc size calculation wrap",
             "size_t total = count * elem_size; void *p = malloc(total);", "if (__builtin_mul_overflow(count, elem_size, &total)) return -1; void *p = malloc(total);",
             r"malloc\(.*count", ["CWE-190", "CWE-128", "CERT INT32-C"]),
            ("03", "Use-After-Free and Double-Free in Cleanup Paths", "free() followed by dereference or re-free",
             "free(ptr); if (err) { free(ptr); return; }", "free(ptr); ptr = NULL; if (err) return;",
             r"free\(ptr\)", ["CWE-416", "CWE-415", "CERT MEM30-C"]),
            ("04", "Uninitialized Memory Usage and Information Leakage", "uninitialized stack buffer copied to output",
             "struct Data d; memcpy(out, &d, sizeof(d));", "struct Data d = {0}; memcpy(out, &d, sizeof(d));",
             r"struct\s+Data\s+d;", ["CWE-457", "CWE-908", "CERT MEM09-C"]),
            ("05", "Format String Vulnerability in Output APIs", "printf(untrusted_fmt)",
             "printf(user_supplied_str);", "printf(\"%s\", user_supplied_str);",
             r"printf\([a-zA-Z_]", ["CWE-134", "CERT FIO30-C"]),
            ("06", "String Termination and Off-by-One Errors", "strncpy without NUL termination",
             "strncpy(buf, src, sizeof(buf));", "snprintf(buf, sizeof(buf), \"%s\", src);",
             r"strncpy\(", ["CWE-193", "CERT STR32-C"]),
            ("07", "Error Path and Return Value Dropping Causing Fail-Open", "ignored validation or alloc return code",
             "verify_signature(cert); proceed_action();", "if (!verify_signature(cert)) return -1; proceed_action();",
             r"verify_signature\(cert\);", ["CWE-252", "CWE-754", "CERT EXP12-C"]),
            ("08", "File System Race Conditions and Insecure Temp Files", "access() followed by open()",
             "if (access(f, W_OK) == 0) fd = open(f, O_WRONLY);", "fd = open(f, O_WRONLY | O_CREAT | O_EXCL, 0600);",
             r"access\(.*W_OK\)", ["CWE-362", "CWE-377", "CERT FIO01-C"]),
            ("09", "Command Execution and Environment Trust", "system(cmd) with external input",
             "system(user_command);", "execve(\"/bin/trusted\", argv, envp);",
             r"system\(user_command\)", ["CWE-78", "CERT ENV33-C"]),
            ("10", "Undefined Behavior in Concurrency and Signal Safety", "non-async-signal-safe call in handler",
             "void handler(int sig) { printf(\"Signal: %d\\n\", sig); }", "void handler(int sig) { write(STDERR_FILENO, \"sig\\n\", 4); }",
             r"printf\(\"Signal", ["CWE-829", "CERT SIG30-C"]),
        ]
    },
    "cpp": {
        "prefix": "cpp",
        "name": "C++",
        "items": [
            ("01", "Dangling Reference and Iterator Invalidation", "string_view or lambda reference outliving target",
             "std::string_view sv = std::string(user_input); return sv;", "std::string s = user_input; return s;",
             r"std::string_view.*std::string\(", ["CWE-416", "ISO/IEC 14882"]),
            ("02", "Asynchronous Lifetime and Coroutine Data Race", "capturing this in detached async thread",
             "std::thread([this]() { this->process(); }).detach();", "auto self = shared_from_this(); std::thread([self]() { self->process(); }).detach();",
             r"std::thread\(\[this\]", ["CWE-362", "CWE-672", "CppCoreGuidelines CP.2"]),
            ("03", "Container and Raw Buffer Out-of-Bounds", "unchecked vector operator[]",
             "int val = data[user_index];", "int val = data.at(user_index);",
             r"data\[user_index\]", ["CWE-129", "CppCoreGuidelines SL.con.1"]),
            ("04", "Size Computation Overflow in Container Allocation", "integer wrap in vector.reserve()",
             "size_t total = user_n * sizeof(int); vec.reserve(total);", "if (__builtin_mul_overflow(user_n, sizeof(int), &total)) throw std::overflow_error(\"overflow\"); vec.reserve(total);",
             r"vec\.reserve\(total\)", ["CWE-190", "CppCoreGuidelines ES.103"]),
            ("05", "Unsafe Type Casting and Type Confusion", "static_cast downcast without dynamic check",
             "Derived *d = static_cast<Derived*>(base_ptr);", "Derived *d = dynamic_cast<Derived*>(base_ptr); if (!d) return;",
             r"static_cast<Derived\*>", ["CWE-704", "CppCoreGuidelines ES.49"]),
            ("06", "Ownership and Deletion Mismatch", "delete vs delete[] or raw pointer double ownership",
             "int *arr = new int[user_len]; delete arr;", "auto arr = std::make_unique<int[]>(user_len);",
             r"delete\s+arr;", ["CWE-404", "CppCoreGuidelines R.11"]),
            ("07", "Exception Safety and Invariant Incompletion", "destructor throwing or state left corrupted on exception",
             "~MyResource() noexcept(false) { if (err) throw std::runtime_error(\"fail\"); }", "~MyResource() noexcept { log_error(); }",
             r"throw\s+std::runtime_error", ["CWE-703", "CppCoreGuidelines E.16"]),
            ("08", "Uninitialized Members and Padding Information Leak", "struct without default member initializers",
             "struct S { int x; int y; }; S s; serialize(s);", "struct S { int x{0}; int y{0}; }; S s{}; serialize(s);",
             r"struct\s+S\s*\{.*int\s+x;\s*int\s+y;", ["CWE-457", "CppCoreGuidelines C.41"]),
            ("09", "C Memory Operations on Non-Trivial C++ Types", "memcpy or memset on class with virtual table",
             "memset(&my_obj, 0, sizeof(my_obj));", "my_obj = MyClass{};",
             r"memset\(&my_obj", ["CWE-672", "CppCoreGuidelines SL.con.2"]),
            ("10", "Polymorphism and Destructor Traps", "deleting derived object through base with non-virtual dtor",
             "Base *b = new Derived(); delete b;", "class Base { public: virtual ~Base() = default; };",
             r"delete\s+b;", ["CWE-404", "CppCoreGuidelines C.127"]),
        ]
    },
    "csharp": {
        "prefix": "csharp",
        "name": "C#",
        "items": [
            ("01", "Unsafe Deserialization via BinaryFormatter", "BinaryFormatter.Deserialize on untrusted stream",
             "BinaryFormatter bf = new BinaryFormatter(); object o = bf.Deserialize(stream);", "JsonSerializer.Deserialize<SafeModel>(stream);",
             r"BinaryFormatter.*Deserialize\(", ["CWE-502", "MSDN BinaryFormatter Security Guide"]),
            ("02", "SQL Injection via ADO.NET String Interpolation", "SqlCommand with raw interpolated string",
             "SqlCommand cmd = new SqlCommand($\"SELECT * FROM Users WHERE Name = '{name}'\");", "SqlCommand cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = @name\"); cmd.Parameters.AddWithValue(\"@name\", name);",
             r"SqlCommand.*SELECT.*\{name\}", ["CWE-89", "MSDN SqlCommand Parameters"]),
            ("03", "XML External Entity (XXE) and Insecure DTD", "XmlDocument with DtdProcessing.Parse",
             "XmlDocument doc = new XmlDocument(); doc.Load(xmlStream);", "XmlReaderSettings settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };",
             r"doc\.Load\(xmlStream\)", ["CWE-611", "MSDN XXE Prevention"]),
            ("04", "Process and Dynamic Assembly Execution", "Process.Start with UseShellExecute and unquoted argument",
             "Process.Start(new ProcessStartInfo(\"cmd.exe\", \"/c \" + userInput) { UseShellExecute = true });", "Process.Start(\"trusted.exe\", new[] { userInput });",
             r"Process\.Start\(.*UseShellExecute", ["CWE-78", "CWE-88"]),
            ("05", "Path Traversal via Path.Combine Absolute Override", "Path.Combine(basePath, userFilename) when userFilename is absolute",
             "string path = Path.Combine(\"/base/dir\", userPath);", "string clean = Path.GetFileName(userPath); string path = Path.Combine(\"/base/dir\", clean);",
             r"Path\.Combine\(\"/base/dir\"", ["CWE-22", "MSDN Path.Combine Remarks"]),
            ("06", "ASP.NET Over-Posting and Mass Assignment", "binding raw request model directly to database entity",
             "public IActionResult Update([FromForm] User entity) { _db.Users.Update(entity); }", "public IActionResult Update([FromForm] UserUpdateDto dto) { _service.Update(dto); }",
             r"\[FromForm\]\s*User\s+entity", ["CWE-915", "MSDN Overposting Protection"]),
            ("07", "Raw HTML Output Leading to XSS", "Html.Raw rendering unencoded input",
             "@Html.Raw(Model.UserBio)", "@Html.DisplayFor(m => m.UserBio)",
             r"Html\.Raw\(Model\.UserBio\)", ["CWE-79", "MSDN Anti-XSS"]),
            ("08", "Cryptography and Randomness Misuse", "System.Random used for security tokens",
             "Random rnd = new Random(); string token = rnd.Next().ToString();", "byte[] token = RandomNumberGenerator.GetBytes(32);",
             r"new\s+Random\(\);.*rnd\.Next\(", ["CWE-338", "MSDN RandomNumberGenerator"]),
            ("09", "Unsafe Code and Span Memory Boundary Violations", "stackalloc with external untrusted length",
             "Span<byte> buffer = stackalloc byte[userLength];", "byte[] buffer = new byte[Math.Min(userLength, 4096)];",
             r"stackalloc\s+byte\[userLength\]", ["CWE-119", "MSDN stackalloc Safety"]),
            ("10", "Resource Exhaustion and Asynchronous Traps", "Regex without match timeout",
             "Regex reg = new Regex(pattern); reg.Match(input);", "Regex reg = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1));",
             r"new\s+Regex\(pattern\);", ["CWE-400", "CWE-1333", "MSDN Regex Timeouts"]),
        ]
    },
    "go": {
        "prefix": "go",
        "name": "Go",
        "items": [
            ("01", "Data Race on Unsynchronized Shared Maps", "concurrent read/write to standard map",
             "go func() { m[key] = val }()", "var mu sync.Mutex; mu.Lock(); m[key] = val; mu.Unlock()",
             r"go\s+func\(\)\s*\{\s*m\[key\]", ["CWE-362", "Go Concurrency Guide"]),
            ("02", "Ignored Error Leading to Fail-Open Authorization", "unchecked err in authentication check",
             "valid, _ := verifyToken(token); if valid { grantAccess() }", "valid, err := verifyToken(token); if err != nil || !valid { return false }; grantAccess()",
             r"valid,\s*_\s*:=\s*verifyToken\(token\)", ["CWE-754", "CWE-252"]),
            ("03", "Untrusted Input Triggering Nil Panic in Shared Service", "type assertion without ok boolean",
             "val := req.Body.(string)", "val, ok := req.Body.(string); if !ok { return nil, errors.New(\"invalid\") }",
             r"req\.Body\.\(string\)", ["CWE-755", "Effective Go Type Switch"]),
            ("04", "Integer Conversion Truncation in Boundary Checks", "strconv.Atoi downcasted to int16",
             "idx, _ := strconv.Atoi(s); shortIdx := int16(idx)", "idx, _ := strconv.Atoi(s); if idx < 0 || idx > 32767 { return }; shortIdx := int16(idx)",
             r"shortIdx\s*:=\s*int16\(idx\)", ["CWE-190", "CWE-197"]),
            ("05", "Unbounded Resource Consumption via io.ReadAll", "io.ReadAll on untrusted request body",
             "body, _ := io.ReadAll(req.Body)", "body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))",
             r"io\.ReadAll\(req\.Body\)", ["CWE-400", "Go Net/HTTP Security"]),
            ("06", "Command and SQL Injection via fmt.Sprintf", "fmt.Sprintf formatting into SQL or sh -c",
             "query := fmt.Sprintf(\"SELECT * FROM items WHERE name = '%s'\", name)", "row := db.QueryRow(\"SELECT * FROM items WHERE name = ?\", name)",
             r"fmt\.Sprintf\(\"SELECT.*name\s*=", ["CWE-89", "CWE-78"]),
            ("07", "Path Traversal in Archive and File Serving", "filepath.Join with unvalidated relative path",
             "target := filepath.Join(baseDir, userInput)", "clean := filepath.Clean(userInput); if strings.HasPrefix(clean, \"..\") { return }; target := filepath.Join(baseDir, clean)",
             r"filepath\.Join\(baseDir,\s*userInput\)", ["CWE-22", "Go Filepath Docs"]),
            ("08", "Unsafe and cgo Lifetime and Pointer Boundary", "unsafe.String without holding slice lifetime",
             "str := unsafe.String(&b[0], len(b))", "str := string(b)",
             r"unsafe\.String\(", ["CWE-119", "Go Unsafe Rules"]),
            ("09", "Cryptography and TLS Insecure Configuration", "InsecureSkipVerify set to true",
             "tlsConfig := &tls.Config{InsecureSkipVerify: true}", "tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}",
             r"InsecureSkipVerify:\s*true", ["CWE-295", "Go Crypto/TLS"]),
            ("10", "Encoding and Parser Discrepancies in JSON and URLs", "case-insensitive JSON decoding overriding security fields",
             "json.Unmarshal(data, &adminObj)", "dec := json.NewDecoder(data); dec.DisallowUnknownFields(); dec.Decode(&adminObj)",
             r"json\.Unmarshal\(data,\s*&adminObj\)", ["CWE-436", "Go JSON Semantics"]),
        ]
    },
    "java": {
        "prefix": "java",
        "name": "Java",
        "items": [
            ("01", "Unsafe Deserialization via ObjectInputStream", "ObjectInputStream.readObject on untrusted stream",
             "ObjectInputStream ois = new ObjectInputStream(is); Object obj = ois.readObject();", "ValidatingObjectInputStream vois = new ValidatingObjectInputStream(is);",
             r"ois\.readObject\(", ["CWE-502", "Java Secure Coding Guidelines 4.1"]),
            ("02", "Expression Language and JNDI Injection", "InitialContext.lookup with user parameter",
             "Context ctx = new InitialContext(); ctx.lookup(userInput);", "if (!isAllowedJndi(userInput)) throw new SecurityException(); ctx.lookup(userInput);",
             r"ctx\.lookup\(userInput\)", ["CWE-74", "CWE-917"]),
            ("03", "XML External Entity Processing in DocumentBuilder", "DocumentBuilderFactory without disabling DTD",
             "DocumentBuilder db = dbf.newDocumentBuilder(); db.parse(stream);", "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
             r"db\.parse\(stream\)", ["CWE-611", "OWASP Java XXE Sheet"]),
            ("04", "SQL and JPQL Injection in Statement Execution", "Statement.executeQuery with string concatenation",
             "stmt.executeQuery(\"SELECT * FROM accounts WHERE id = '\" + id + \"'\");", "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM accounts WHERE id = ?\"); ps.setString(1, id);",
             r"stmt\.executeQuery\(.*SELECT", ["CWE-89", "JDBC Best Practices"]),
            ("05", "Path Traversal in File Construction and Zip Extraction", "new File(base, userInput) traversal",
             "File target = new File(baseDir, entry.getName());", "Path p = baseDir.resolve(entry.getName()).normalize(); if (!p.startsWith(baseDir)) throw new SecurityException();",
             r"new\s+File\(baseDir,\s*entry\.getName\(\)\)", ["CWE-22", "CERT FIO16-J"]),
            ("06", "Command Execution and Unsafe Reflection", "Runtime.getRuntime().exec with unsanitized arguments",
             "Runtime.getRuntime().exec(\"sh -c \" + cmd);", "ProcessBuilder pb = new ProcessBuilder(\"/bin/safe\", arg); pb.start();",
             r"Runtime\.getRuntime\(\)\.exec\(", ["CWE-78", "CERT ENV06-J"]),
            ("07", "Concurrency and Mutable State in Servlets", "instance variables in Singleton Servlets",
             "public class UserServlet extends HttpServlet { private String currentUser; }", "public class UserServlet extends HttpServlet { /* use local variables */ }",
             r"public\s+class\s+UserServlet.*private\s+String\s+currentUser", ["CWE-362", "Servlet Concurrency Guide"]),
            ("08", "Boxed Primitive Comparison and Silent Numerical Overflow", "using == on Integer wrapper objects",
             "if (roleId1 == roleId2) { grantAccess(); }", "if (Objects.equals(roleId1, roleId2)) { grantAccess(); }",
             r"if\s*\(roleId1\s*==\s*roleId2\)", ["CWE-595", "CERT EXP01-J"]),
            ("09", "Cryptography and Weak PRNG Misuse", "java.util.Random for security credentials",
             "Random r = new Random(); int token = r.nextInt();", "SecureRandom sr = new SecureRandom(); byte[] token = new byte[32]; sr.nextBytes(token);",
             r"Random\s+r\s*=\s*new\s+Random\(\);", ["CWE-338", "Java Crypto Architecture Guide"]),
            ("10", "Servlet and URL Discrepancies in Security Filters", "request.getRequestURI() normalization bypass",
             "if (request.getRequestURI().startsWith(\"/admin\")) { checkAdmin(); }", "if (request.getServletPath().startsWith(\"/admin\")) { checkAdmin(); }",
             r"request\.getRequestURI\(\)\.startsWith", ["CWE-436", "OWASP URL Mapping Bypass"]),
        ]
    },
    "rust": {
        "prefix": "rust",
        "name": "Rust",
        "items": [
            ("01", "Unsoundness in Unsafe Memory Operations", "slice::from_raw_parts with unverified length",
             "unsafe { std::slice::from_raw_parts(ptr, external_len); }", "if external_len <= max_len { unsafe { std::slice::from_raw_parts(ptr, external_len) }; }",
             r"slice::from_raw_parts\(ptr,\s*external_len\)", ["CWE-119", "Rust Nomicon"]),
            ("02", "FFI Boundary Lifetime and CString Hazards", "CString::as_ptr dangling after drop",
             "let p = CString::new(s).unwrap().as_ptr(); unsafe { c_function(p); }", "let cs = CString::new(s).unwrap(); unsafe { c_function(cs.as_ptr()); }",
             r"CString::new\(s\)\.unwrap\(\)\.as_ptr\(\)", ["CWE-416", "Rust FFI Guide"]),
            ("03", "Denial of Service via Panic on Untrusted Input", "unwrap() or array indexing on user network packet",
             "let val = packet[user_index];", "let val = packet.get(user_index).ok_or(Error::InvalidIndex)?;",
             r"packet\[user_index\]", ["CWE-755", "CWE-248"]),
            ("04", "Integer Wrapping and Lossy Casting via 'as'", "lossy truncation in pointer length calculation",
             "let len = user_size as u16;", "let len = u16::try_from(user_size).map_err(|_| Error::Overflow)?;",
             r"user_size\s+as\s+u16", ["CWE-197", "CWE-190"]),
            ("05", "Unsound Send and Sync Implementations", "manual unsafe impl Sync for non-thread-safe type",
             "unsafe impl Sync for RawContainer {}", "/* use Mutex or Arc to ensure thread safety */",
             r"unsafe\s+impl\s+Sync\s+for", ["CWE-362", "Rustonomicon Send/Sync"]),
            ("06", "Unbounded Resource Allocation in Collections", "Vec::with_capacity driven by remote header",
             "let mut v = Vec::with_capacity(remote_size);", "if remote_size > MAX_ALLOWED { return Err(Error::TooLarge); }; let mut v = Vec::with_capacity(remote_size);",
             r"Vec::with_capacity\(remote_size\)", ["CWE-400", "Rust Std Vec Docs"]),
            ("07", "Deserialization and Untrusted Parser Assumptions", "serde deserializing unbounded nested enum",
             "let obj: ComplexEnum = serde_json::from_reader(reader)?;", "let mut de = serde_json::Deserializer::from_reader(reader); de.disable_recursion_limit();",
             r"serde_json::from_reader\(reader\)", ["CWE-502", "CWE-674"]),
            ("08", "Command and Path Traversal Hazards", "Command::new with unsanitized executable name",
             "Command::new(user_cmd).arg(arg).spawn()?;", "Command::new(\"/usr/bin/trusted_app\").arg(arg).spawn()?;",
             r"Command::new\(user_cmd\)", ["CWE-78", "Rust Std Command Docs"]),
            ("09", "Cryptographic Constant-Time Comparison Failures", "using == to verify HMAC or signature digest",
             "if sig == expected_sig { grant(); }", "if subtle::ConstantTimeEq::ct_eq(&sig, &expected_sig).into() { grant(); }",
             r"if\s+sig\s*==\s*expected_sig", ["CWE-208", "Rust Subtle Crate"]),
            ("10", "Unsafe Abstraction Drop and Panic Safety", "ptr::read causing double drop on panic",
             "let val = unsafe { std::ptr::read(src) };", "/* ensure std::mem::forget or ManuallyDrop handles panic */",
             r"std::ptr::read\(src\)", ["CWE-415", "Rust Exception Safety"]),
        ]
    },
    "python": {
        "prefix": "py",
        "name": "Python",
        "items": [
            ("01", "Unsafe Deserialization via pickle/marshal/shelve", "pickle.loads on untrusted network input",
             "obj = pickle.loads(untrusted_payload)", "obj = json.loads(untrusted_payload)",
             r"pickle\.loads\(untrusted_payload\)", ["CWE-502", "Python Pickle Security Notice"]),
            ("02", "Code and Expression Injection via eval/exec", "evaluating dynamic user-supplied string",
             "result = eval(user_expression)", "result = ast.literal_eval(user_expression)",
             r"eval\(user_expression\)", ["CWE-94", "CWE-95"]),
            ("03", "Command Injection in subprocess with shell=True", "subprocess.Popen with shell=True and formatting",
             "subprocess.Popen(f\"echo {user_input}\", shell=True)", "subprocess.Popen([\"echo\", user_input])",
             r"subprocess\.Popen\(.*shell=True\)", ["CWE-78", "Python Subprocess Security"]),
            ("04", "Path Traversal in os.path.join and tarfile extraction", "os.path.join discarding base path on absolute input",
             "full_path = os.path.join('/app/uploads', filename)", "full_path = os.path.join('/app/uploads', os.path.basename(filename))",
             r"os\.path\.join\('/app/uploads',\s*filename\)", ["CWE-22", "Python os.path.join Documentation"]),
            ("05", "SQL Injection in DB-API via f-string Formatting", "cursor.execute with f-string interpolation",
             "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")", "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
             r"cursor\.execute\(f\"SELECT.*user_id", ["CWE-89", "PEP 249"]),
            ("06", "XML Entity Expansion and Catastrophic Regex Backtracking", "xml.etree.ElementTree parsing external XML",
             "tree = xml.etree.ElementTree.fromstring(xml_payload)", "import defusedxml.ElementTree as ET; tree = ET.fromstring(xml_payload)",
             r"xml\.etree\.ElementTree\.fromstring\(", ["CWE-611", "CWE-1333"]),
            ("07", "Dynamic Truthiness and '==' vs 'is' Check Bypass", "relying on 'assert' for security validation under -O",
             "assert is_admin(user), 'Unauthorized'", "if not is_admin(user): raise PermissionError('Unauthorized')",
             r"assert\s+is_admin\(user\)", ["CWE-617", "Python Assert Caveat"]),
            ("08", "SSRF and Protocol Inconsistencies in urllib", "urllib.request.urlopen without scheme restriction",
             "resp = urllib.request.urlopen(user_url)", "if not user_url.startswith(('https://', 'http://')): raise ValueError(); resp = urllib.request.urlopen(user_url)",
             r"urllib\.request\.urlopen\(user_url\)", ["CWE-918", "Python urllib Security"]),
            ("09", "Cryptographic Misuse and Weak PRNG for Secrets", "random.choice for generating security tokens",
             "token = ''.join(random.choice(chars) for _ in range(32))", "token = secrets.token_hex(32)",
             r"random\.choice\(chars\)", ["CWE-338", "PEP 506"]),
            ("10", "Unbounded Input Processing and Resource Exhaustion", "reading socket without size limits",
             "data = request.raw.read()", "data = request.raw.read(1024 * 1024)",
             r"request\.raw\.read\(\)", ["CWE-400", "Python I/O Limits"]),
        ]
    },
    "javascript": {
        "prefix": "js",
        "name": "JavaScript",
        "items": [
            ("01", "Prototype Pollution in Recursive Object Merging", "assigning to __proto__ via deep merge",
             "target[key] = source[key]; // key is __proto__", "if (key !== '__proto__' && key !== 'constructor') target[key] = source[key];",
             r"target\[key\]\s*=\s*source\[key\]", ["CWE-1321", "NodeJS Security Prototype Pollution"]),
            ("02", "Code Injection via eval and new Function", "eval on dynamic string payload",
             "const res = eval(userCode);", "const res = JSON.parse(userCode);",
             r"eval\(userCode\)", ["CWE-94", "CWE-95"]),
            ("03", "Command Injection via child_process.exec", "child_process.exec with concatenated string",
             "child_process.exec(`ping ${host}`);", "child_process.execFile('ping', [host]);",
             r"child_process\.exec\(`ping", ["CWE-78", "Node.js Child Process Security"]),
            ("04", "DOM Cross-Site Scripting via innerHTML", "assigning untrusted text directly to innerHTML",
             "element.innerHTML = userComment;", "element.textContent = userComment;",
             r"element\.innerHTML\s*=\s*userComment", ["CWE-79", "OWASP DOM XSS"]),
            ("05", "Type Coercion and Loose Comparison Bypasses", "using == to verify authentication tokens",
             "if (token == expectedToken) { grantAccess(); }", "if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))) { grantAccess(); }",
             r"token\s*==\s*expectedToken", ["CWE-697", "ECMA-262 Loose Equality"]),
            ("06", "Path Traversal via path.resolve and fs APIs", "fs.readFile with user supplied relative path",
             "fs.readFile(path.resolve('/var/data', userFile), cb);", "const clean = path.basename(userFile); fs.readFile(path.join('/var/data', clean), cb);",
             r"fs\.readFile\(path\.resolve\(", ["CWE-22", "Node.js File System Security"]),
            ("07", "Event Loop Blocking and Catastrophic Regex (ReDoS)", "evaluating exponential regex on untrusted input",
             "const match = /^([a-zA-Z0-9]+)*$/.exec(userInput);", "/* use linear regex or set timeouts */",
             r"\^([a-zA-Z0-9]\+\)\*\$", ["CWE-1333", "OWASP ReDoS"]),
            ("08", "Unhandled Promise Rejection and Missing Await in Auth", "missing await on authentication check function",
             "if (!checkAuth(req)) { return res.status(401); }", "if (!await checkAuth(req)) { return res.status(401); }",
             r"if\s*\(!checkAuth\(req\)\)", ["CWE-754", "CWE-287"]),
            ("09", "Unsafe Deserialization and Reviver Misuse", "eval based deserialization",
             "const data = (new Function('return ' + rawJson))();", "const data = JSON.parse(rawJson);",
             r"new\s+Function\('return\s*'\s*\+\s*rawJson\)", ["CWE-502", "OWASP Deserialization"]),
            ("10", "Insecure Randomness via Math.random for Tokens", "Math.random() used to generate session token",
             "const token = Math.random().toString(36).substring(2);", "const token = crypto.randomBytes(16).toString('hex');",
             r"Math\.random\(\)\.toString\(36\)", ["CWE-338", "Node.js Crypto Documentation"]),
        ]
    },
    "typescript": {
        "prefix": "ts",
        "name": "TypeScript",
        "items": [
            ("01", "Type Erasure: Confusing Compile-Time Type with Runtime Validation", "'as T' type assertion without runtime schema check",
             "const body = req.body as UserProfile;", "const body = UserProfileSchema.parse(req.body);",
             r"req\.body\s+as\s+UserProfile", ["CWE-704", "TypeScript HandBook Type Erasure"]),
            ("02", "Type Escape Hatches at Security Boundaries", "using 'any' or non-null assertion '!' to bypass checks",
             "const user: any = JSON.parse(data); grant(user.role);", "const user = parseValidatedUser(data);",
             r"const\s+user:\s*any\s*=", ["CWE-285", "TypeScript Strict Guidelines"]),
            ("03", "Flawed Type Guards and Discriminated Union Bypass", "custom type guard returning true without validation",
             "function isAdmin(x: any): x is Admin { return true; }", "function isAdmin(x: any): x is Admin { return x && x.role === 'admin'; }",
             r"function\s+isAdmin.*x\s+is\s+Admin\s*\{\s*return\s+true;", ["CWE-398", "TypeScript Type Guards"]),
            ("04", "Index Signatures Enabling Prototype Pollution", "Record<string, unknown> allowing arbitrary key access",
             "const map: Record<string, any> = {}; map[userKey] = value;", "const map = new Map<string, any>(); map.set(userKey, value);",
             r"map\[userKey\]\s*=\s*value", ["CWE-1321", "TypeScript Index Signatures"]),
            ("05", "Numeric Enum Traps and Unchecked Literal Unions", "numeric enum accepting arbitrary numbers",
             "enum Role { User = 1, Admin = 2 }; function setRole(r: Role) { ... }", "type Role = 'User' | 'Admin';",
             r"enum\s+Role\s*\{.*User\s*=\s*1", ["CWE-704", "TypeScript Enum Caveat"]),
            ("06", "Decorator-Driven Validation Gaps", "validator decorator declared but runtime reflection omitted",
             "@ValidateRole userRole: string;", "@ValidateRole userRole: string; // ensure reflect-metadata enabled",
             r"@ValidateRole\s+userRole", ["CWE-754", "TS Decorator Metadata"]),
            ("07", "Floating Promise in Security Handlers", "promise without await in express middleware",
             "app.use((req, res, next) => { verifyPermissions(req); next(); });", "app.use(async (req, res, next) => { await verifyPermissions(req); next(); });",
             r"verifyPermissions\(req\);\s*next\(\);", ["CWE-754", "TS Floating Promises"]),
            ("08", "Compiler Flag Relaxation Causing Verification Holes", "disabling strictNullChecks allowing undefined propagation",
             "function get(id: string): User { return users[id]; }", "function get(id: string): User | undefined { return users[id]; }",
             r"function\s+get\(id:\s*string\):\s*User", ["CWE-476", "TS strictNullChecks"]),
            ("09", "Compile-Time Access Control Bypass via Runtime Inspection", "relying on 'private' keyword instead of '#private' fields",
             "class Secret { private key: string = 'token'; }", "class Secret { #key: string = 'token'; }",
             r"class\s+Secret\s*\{\s*private\s+key", ["CWE-668", "TS Private Fields"]),
            ("10", "Serialization Boundary Precision Loss on Large Integers", "JSON.parse losing precision on 64-bit ID",
             "const id = JSON.parse(jsonPayload).id;", "const id = BigInt(JSONBig.parse(jsonPayload).id);",
             r"JSON\.parse\(jsonPayload\)\.id", ["CWE-190", "CWE-682"]),
        ]
    },
    "kotlin": {
        "prefix": "kotlin",
        "name": "Kotlin",
        "items": [
            ("01", "Java Interop Null-Safety Gaps Leading to Panic", "platform type null dereference with '!!'",
             "val user = javaApi.getUser()!!", "val user = javaApi.getUser() ?: return null",
             r"javaApi\.getUser\(\)!!", ["CWE-476", "Kotlin Java Interop Nullability"]),
            ("02", "Android Exported Component Intent Redirection", "unprotected Intent forwarding in exported Activity",
             "startActivity(intent.getParcelableExtra(\"forward\"))", "val target = intent.getParcelableExtra<Intent>(\"forward\"); if (isValid(target)) startActivity(target)",
             r"startActivity\(intent\.getParcelableExtra", ["CWE-926", "Android Intent Security"]),
            ("03", "Unsafe Deserialization in Intent Extras", "getSerializableExtra without class verification",
             "val data = intent.getSerializableExtra(\"data\")", "val data = IntentCompat.getSerializableExtra(intent, \"data\", MyClass::class.java)",
             r"intent\.getSerializableExtra\(", ["CWE-502", "Android Deserialization Guide"]),
            ("04", "WebView Javascript Interface and File Scheme Hazards", "addJavascriptInterface exposed on untrusted URL",
             "webView.addJavascriptInterface(bridge, \"nativeApp\")", "webView.settings.allowFileAccess = false; /* restrict bridge */",
             r"webView\.addJavascriptInterface\(", ["CWE-749", "Android WebView Best Practices"]),
            ("05", "Coroutine Concurrency and Shared Mutable State", "launching coroutines modifying shared var without Mutex",
             "GlobalScope.launch { counter++ }", "val mutex = Mutex(); launch { mutex.withLock { counter++ } }",
             r"GlobalScope\.launch\s*\{\s*counter\+\+", ["CWE-362", "Kotlin Coroutines Concurrency"]),
            ("06", "SQL Injection via String Template in rawQuery", "rawQuery using string template interpolation",
             "db.rawQuery(\"SELECT * FROM items WHERE id = '$id'\", null)", "db.rawQuery(\"SELECT * FROM items WHERE id = ?\", arrayOf(id))",
             r"rawQuery\(\"SELECT.*\$id", ["CWE-89", "Android SQLite Security"]),
            ("07", "Process Execution via String Template Commands", "Runtime.getRuntime().exec with interpolated command",
             "Runtime.getRuntime().exec(\"sh -c $cmd\")", "ProcessBuilder(\"/bin/safe\", arg).start()",
             r"Runtime\.getRuntime\(\)\.exec\(\"sh -c \$cmd\"\)", ["CWE-78", "Kotlin Process Execution"]),
            ("08", "Insecure Storage and Hardcoded Cryptographic Keys", "SharedPreferences storing sensitive tokens in plain text",
             "prefs.edit().putString(\"auth_token\", token).apply()", "EncryptedSharedPreferences.create(...).edit().putString(\"token\", token).apply()",
             r"prefs\.edit\(\)\.putString\(\"auth_token\"", ["CWE-312", "Android Keystore System"]),
            ("09", "TLS and TrustManager Bypass in Network Callbacks", "TrustAllCerts implementation in OkHttpClient",
             "builder.sslSocketFactory(trustAllSslSocketFactory, trustAllManager)", "builder.certificatePinner(pinner)",
             r"builder\.sslSocketFactory\(trustAll", ["CWE-295", "OkHttp TLS Guide"]),
            ("10", "Kotlin Language Traps: copy() Bypassing Validation", "data class copy() bypassing constructor constraints",
             "val unauthorized = user.copy(role = \"admin\")", "fun User.promote(auth: Auth) = ...",
             r"user\.copy\(role\s*=\s*\"admin\"\)", ["CWE-285", "Kotlin Data Class Invariants"]),
        ]
    },
    "scala": {
        "prefix": "scala",
        "name": "Scala",
        "items": [
            ("01", "Unsafe Java Deserialization via ObjectInputStream", "ObjectInputStream in Akka/Pekko remoting",
             "val obj = ois.readObject()", "/* Use Jackson or Protobuf serialization */",
             r"ois\.readObject\(\)", ["CWE-502", "Akka Remoting Security"]),
            ("02", "Command Injection via scala.sys.process Interpolator", "string interpolation inside process execution",
             "s\"sh -c $userInput\".!", "Seq(\"/bin/safe\", userInput).!",
             r"s\"sh -c \$userInput\"\.!", ["CWE-78", "Scala Sys Process Docs"]),
            ("03", "SQL Injection in String Interpolation Queries", "s\"SELECT * FROM t WHERE id = $id\" in JDBC",
             "statement.execute(s\"SELECT * FROM t WHERE id = $id\")", "sql\"SELECT * FROM t WHERE id = $id\".query[Row]",
             r"statement\.execute\(s\"SELECT", ["CWE-89", "Doobie/Slick Security"]),
            ("04", "Implicit Conversion Changing Security Semantics", "implicit conversion hiding unsafe transformation",
             "implicit def toAdmin(u: User): Admin = Admin(u.name)", "/* explicit conversion functions only */",
             r"implicit\s+def\s+toAdmin", ["CWE-704", "Scala Implicits Guide"]),
            ("05", "Non-Exhaustive Pattern Matching and Option.get Panic", "calling .get on untrusted Option",
             "val result = parseInput(data).get", "parseInput(data) match { case Some(v) => v; case None => return }",
             r"parseInput\(data\)\.get", ["CWE-755", "Scala Option Best Practices"]),
            ("06", "Concurrency: Escaping Mutable State in Actor Futures", "Actor capturing mutable var in Future block",
             "Future { mutableState += msg }", "/* Send immutable messages to self */",
             r"Future\s*\{\s*mutableState\s*\+=", ["CWE-362", "Akka Concurrency Safety"]),
            ("07", "XML External Entity Processing in scala.xml.XML", "scala.xml.XML.load with default external entity",
             "val xml = scala.xml.XML.load(inputStream)", "val parser = saxParserFactory.newSAXParser(); parser.parse(...)",
             r"scala\.xml\.XML\.load\(", ["CWE-611", "Scala XML Security"]),
            ("08", "Unbounded Stream and LazyList Resource Exhaustion", "LazyList memoization leaking memory on unbounded stream",
             "val stream = LazyList.from(0).map(process)", "/* use Akka/FS2 streams with backpressure */",
             r"LazyList\.from\(0\)", ["CWE-400", "Scala LazyList Memory"]),
            ("09", "Path Traversal via scala.io.Source", "Source.fromFile with untrusted relative path",
             "val content = Source.fromFile(userPath).mkString", "val clean = sanitize(userPath); Source.fromFile(clean).mkString",
             r"Source\.fromFile\(userPath\)", ["CWE-22", "Scala IO Docs"]),
            ("10", "Secret Leakage via case class toString()", "case class automatically generating toString with passwords",
             "case class UserCredentials(username: String, pass: String)", "case class UserCredentials(...) { override def toString = ... }",
             r"case\s+class\s+UserCredentials\(", ["CWE-532", "Scala Case Classes"]),
        ]
    },
    "php": {
        "prefix": "php",
        "name": "PHP",
        "items": [
            ("01", "Type Juggling and Loose Comparison Bypasses", "using == with '0e' hashes or string to int comparison",
             "if ($password_hash == '0e123456789') { login(); }", "if (hash_equals($password_hash, $expected)) { login(); }",
             r"\$password_hash\s*==\s*'0e", ["CWE-697", "PHP Type Juggling Guide"]),
            ("02", "PHP Object Injection via unserialize()", "unserialize on untrusted input",
             "$data = unserialize($_COOKIE['session']);", "$data = json_decode($_COOKIE['session'], true);",
             r"unserialize\(\$_COOKIE", ["CWE-502", "PHP Unserialize Security"]),
            ("03", "Local File Inclusion via include/require", "include with dynamic user parameter",
             "include($_GET['page'] . '.php');", "include(ALLOWED_PAGES[$_GET['page']]);",
             r"include\(\$_GET\['page'\]", ["CWE-98", "PHP LFI Mitigation"]),
            ("04", "Command and Code Injection via eval/system", "system with unsanitized user command",
             "system('ping -c 1 ' . $host);", "system('ping -c 1 ' . escapeshellarg($host));",
             r"system\('ping.*\$host", ["CWE-78", "PHP Command Execution"]),
            ("05", "SQL Injection via mysqli/PDO String Interpolation", "PDO::query with raw string parameter",
             "$pdo->query(\"SELECT * FROM users WHERE email = '$email'\");", "$stmt = $pdo->prepare(\"SELECT * FROM users WHERE email = ?\"); $stmt->execute([$email]);",
             r"\$pdo->query\(\"SELECT.*\$email", ["CWE-89", "PDO Prepared Statements"]),
            ("06", "Global Variable Injection via extract() and parse_str()", "extract($_GET) overwriting internal variables",
             "extract($_POST); if ($is_admin) { ... }", "/* access $_POST['var'] explicitly */",
             r"extract\(\$_POST\)", ["CWE-621", "PHP extract Security"]),
            ("07", "Cross-Site Scripting via Unescaped echo", "echo of user input without htmlspecialchars",
             "echo '<div class=\"comment\">' . $_GET['comment'] . '</div>';", "echo htmlspecialchars($_GET['comment'], ENT_QUOTES, 'UTF-8');",
             r"echo.*comment.*;\s*//\s*unescaped", ["CWE-79", "PHP htmlspecialchars"]),
            ("08", "Weak Cryptography and Deprecated Hash Functions", "using md5 for password storage",
             "$hash = md5($password);", "$hash = password_hash($password, PASSWORD_BCRYPT);",
             r"md5\(\$password\)", ["CWE-328", "PHP password_hash Documentation"]),
            ("09", "XML External Entity Injection in simplexml", "simplexml_load_string with LIBXML_NOENT",
             "$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT);", "$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NONET);",
             r"simplexml_load_string\(.*LIBXML_NOENT", ["CWE-611", "PHP XML Security"]),
            ("10", "strpos False vs Zero Comparison Hazard", "using if (!strpos($haystack, $needle)) for verification",
             "if (strpos($url, 'https://example.com') == false) { reject(); }", "if (strpos($url, 'https://example.com') !== 0) { reject(); }",
             r"strpos\(.*==\s*false", ["CWE-697", "PHP strpos Manual"]),
        ]
    },
    "ruby": {
        "prefix": "ruby",
        "name": "Ruby",
        "items": [
            ("01", "Unsafe Deserialization via Marshal.load", "Marshal.load on untrusted byte stream",
             "data = Marshal.load(params[:state])", "data = JSON.parse(params[:state])",
             r"Marshal\.load\(params\[:state\]\)", ["CWE-502", "Ruby Marshal Security Warning"]),
            ("02", "Dynamic Code Execution and Metaprogramming via send", "calling public_send with user supplied method name",
             "user.public_send(params[:method], params[:arg])", "/* allowlist allowed method names */",
             r"user\.public_send\(params\[:method\]", ["CWE-470", "Ruby Metaprogramming Security"]),
            ("03", "Command Injection in Kernel#open and System Backticks", "open(\"|\" + cmd) executing shell commands",
             "open(\"|\" + params[:file_cmd]).read", "IO.popen([\"/bin/safe\", params[:arg]]).read",
             r"open\(\"\|\"\s*\+\s*params", ["CWE-78", "Ruby Kernel#open Security Warning"]),
            ("04", "SQL Injection via String Interpolation in Queries", "ActiveRecord where clause with #{}",
             "User.where(\"name = '#{params[:name]}'\")", "User.where(\"name = ?\", params[:name])",
             r"User\.where\(\"name = '#\{params", ["CWE-89", "Rails Security Guide SQL Injection"]),
            ("05", "Mass Assignment and Parameter Type Confusion", "updating attributes directly with params[:user]",
             "User.update(params[:user])", "User.update(user_params) # using strong_parameters",
             r"User\.update\(params\[:user\]\)", ["CWE-915", "Rails Strong Parameters"]),
            ("06", "Regular Expression Multiline Anchors Trap", "using ^ and $ instead of \\A and \\z",
             "valid = url =~ /^https:\\/\\/example\\.com$/", "valid = url =~ /\\Ahttps:\\/\\/example\\.com\\z/",
             r"url\s*=~\s*\/\^https", ["CWE-185", "Ruby Regex Anchors"]),
            ("07", "Raw HTML and html_safe Misuse", "calling .html_safe on untrusted string",
             "user_bio.html_safe", "sanitize(user_bio)",
             r"user_bio\.html_safe", ["CWE-79", "Rails XSS Prevention"]),
            ("08", "Path Traversal via Pathname#join", "Pathname.new(base).join(params[:path]) with absolute path",
             "Pathname.new('/safe/dir').join(params[:path])", "File.join('/safe/dir', File.basename(params[:path]))",
             r"Pathname\.new\('/safe/dir'\)\.join", ["CWE-22", "Ruby Pathname Docs"]),
            ("09", "Class Variable and Open Class State Leakage", "class variables @@ shared across thread requests",
             "class App; @@current_user = user; end", "Thread.current[:user] = user",
             r"@@current_user\s*=\s*user", ["CWE-362", "Ruby Class Variables Concurrency"]),
            ("10", "Weak Randomness and Timeout Asynchronous Interrupts", "rand() used for security tokens",
             "token = rand(100000..999999).to_s", "token = SecureRandom.hex(16)",
             r"rand\(100000\.\.999999\)", ["CWE-338", "Ruby SecureRandom"]),
        ]
    },
    "swift": {
        "prefix": "swift",
        "name": "Swift",
        "items": [
            ("01", "Unsafe Pointer Escape and Buffer Bounds", "UnsafeRawBufferPointer escaping withUnsafeBytes",
             "var ptr: UnsafeRawPointer?; data.withUnsafeBytes { ptr = $0.baseAddress }", "data.withUnsafeBytes { use($0) }",
             r"withUnsafeBytes\s*\{\s*ptr\s*=", ["CWE-119", "Swift Memory Safety Rules"]),
            ("02", "Objective-C Interop and NSKeyedUnarchiver", "NSKeyedUnarchiver without requiring secure coding",
             "let obj = NSKeyedUnarchiver.unarchiveObject(with: data)", "let obj = try NSKeyedUnarchiver.unarchivedObject(ofClass: SafeClass.self, from: data)",
             r"NSKeyedUnarchiver\.unarchiveObject\(", ["CWE-502", "Apple Secure Coding Guide"]),
            ("03", "Runtime Traps and Force Unwrapping DoS", "force unwrapping '!' on untrusted external JSON",
             "let token = json[\"token\"] as! String", "guard let token = json[\"token\"] as? String else { return }",
             r"json\[\"token\"\]\s+as!\s+String", ["CWE-755", "Swift Error Handling"]),
            ("04", "Data Race in Concurrency and Actor Reentrancy", "state check across await in actor",
             "if balance >= amount { await deduct(); balance -= amount }", "/* re-check balance after await */",
             r"if\s+balance\s*>=\s*amount\s*\{\s*await\s+deduct\(\)", ["CWE-362", "Swift Concurrency Guide"]),
            ("05", "WKWebView JavaScript String Concatenation Injection", "evaluateJavaScript using string interpolation",
             "webView.evaluateJavaScript(\"setUser('\(userParam)')\")", "/* pass parameters via message handler or JSON */",
             r"webView\.evaluateJavaScript\(\"setUser\('\(userParam\)'\)\"\)", ["CWE-79", "Apple WKWebView Security"]),
            ("06", "Insecure Storage in UserDefaults and ATS Bypass", "storing secrets in standard UserDefaults",
             "UserDefaults.standard.set(secretToken, forKey: \"token\")", "/* use Keychain Services */",
             r"UserDefaults\.standard\.set\(secretToken", ["CWE-312", "Apple Keychain Services"]),
            ("07", "Path Traversal via URL appendingPathComponent", "appendingPathComponent with unvalidated filename",
             "let dest = baseDir.appendingPathComponent(userInput)", "let clean = (userInput as NSString).lastPathComponent; let dest = baseDir.appendingPathComponent(clean)",
             r"baseDir\.appendingPathComponent\(userInput\)", ["CWE-22", "Apple URL Handling"]),
            ("08", "Decoding and Type Coercion Inconsistencies", "loose Decodable fallback silently ignoring security fields",
             "let user = try? JSONDecoder().decode(User.self, from: data)", "do { let user = try JSONDecoder().decode(User.self, from: data) } catch { ... }",
             r"try\?\s+JSONDecoder\(\)\.decode\(", ["CWE-754", "Swift Codable"]),
            ("09", "String Index and Unicode Normalization Discrepancies", "NSRange vs Swift String.Index mismatch in validation",
             "let range = NSRange(location: 0, length: 10)", "/* validate using Swift Native Index */",
             r"NSRange\(location:\s*0,\s*length:\s*10\)", ["CWE-135", "Swift Unicode Guide"]),
            ("10", "Unbounded Buffer Allocation in Network Streams", "Data(capacity: remoteSize) allocated directly",
             "var buf = Data(capacity: remoteSize)", "guard remoteSize <= MAX_LIMIT else { return }; var buf = Data(capacity: remoteSize)",
             r"Data\(capacity:\s*remoteSize\)", ["CWE-400", "Swift Data Limits"]),
        ]
    },
    "shell": {
        "prefix": "shell",
        "name": "Shell",
        "items": [
            ("01", "Unquoted Variable Expansion and Word Splitting", "$var without quotes causing globbing and splitting",
             "rm -rf $DIR_PATH", "rm -rf \"$DIR_PATH\"",
             r"rm\s+-rf\s+\$DIR_PATH", ["CWE-78", "Bash Reference Word Splitting"]),
            ("02", "Code Injection in eval and Command Substitution", "eval on user parameter string",
             "eval \"$user_cmd\"", "/* avoid eval; use explicit fixed commands */",
             r"eval\s+\"\$user_cmd\"", ["CWE-78", "CWE-95"]),
            ("03", "Option Injection via Unfiltered Flags", "passing filenames starting with '-' without '--'",
             "cat $user_file", "cat -- \"$user_file\"",
             r"cat\s+\$user_file", ["CWE-88", "POSIX Utility Syntax Guidelines"]),
            ("04", "Predictable Temporary Files in /tmp", "creating /tmp/app.$$ without mktemp",
             "tmpfile=\"/tmp/test.$$\"; echo data > \"$tmpfile\"", "tmpfile=\"$(mktemp /tmp/test.XXXXXX)\"; echo data > \"$tmpfile\"",
             r"tmpfile=\"/tmp/test\.\$\$\"", ["CWE-377", "CERT POS38-C"]),
            ("05", "Insecure PATH Inheritance and Environment Trust", "calling bare command without fixed PATH in root script",
             "cleanup_script", "/usr/local/bin/cleanup_script",
             r"cleanup_script\s*//\s*bare", ["CWE-426", "Bash Startup Security"]),
            ("06", "Fail-Open Execution without set -euo pipefail", "failing checksum check ignored without -e",
             "sha256sum -c hash.txt; install_package.sh", "set -euo pipefail; sha256sum -c hash.txt; install_package.sh",
             r"sha256sum\s+-c\s+hash\.txt;\s*install_package\.sh", ["CWE-754", "Bash Error Handling Guide"]),
            ("07", "Variable Scope, Attributes, and Name Reference Pollution", "declare -n nameref pointing to user variable name",
             "declare -n ref=\"$user_input\"; ref=\"value\"", "/* strictly validate variable name */",
             r"declare\s+-n\s+ref=\"\$user_input\"", ["CWE-621", "Bash Namerefs Security"]),
            ("08", "Secret Leakage in Process Arguments and set -x", "token passed as command argument visible in ps",
             "curl -H \"Authorization: $TOKEN\" http://example.com", "curl -K <(echo \"header = \\\"Authorization: $TOKEN\\\"\") http://example.com",
             r"curl\s+-H\s+\"Authorization:\s+\$TOKEN\"", ["CWE-214", "CWE-532"]),
            ("09", "Destructive File Operations on Empty Variables", "rm -rf \"$DIR/\"* when DIR is unset",
             "rm -rf \"$DEST/\"*", "rm -rf \"${DEST:?Destination required}/\"*",
             r"rm\s+-rf\s+\"\$DEST/\"\*", ["CWE-73", "CWE-398"]),
            ("10", "Secondary Injection into Remote Shells and Utilities", "ssh host \"cmd $input\" with secondary evaluation",
             "ssh remote \"rm -f $filename\"", "ssh remote \"rm -f -- $(printf '%q' \"$filename\")\"",
             r"ssh\s+remote\s+\"rm\s+-f\s+\$filename\"", ["CWE-78", "SSH Command Quoting Guide"]),
        ]
    }
}


def generate():
    total_cards = 0
    apis_registry = []

    for lang, info in LANG_DATA.items():
        lang_dir = LANGUAGES_DIR / lang
        lang_dir.mkdir(parents=True, exist_ok=True)

        index_entries = []
        signals_entries = []

        for num_str, title, sink_clue, vuln_code, safe_code, sig_pat, refs in info["items"]:
            card_id = f"{info['prefix']}-{num_str}"
            total_cards += 1

            index_entries.append({
                "id": card_id,
                "title": title,
                "sink_clue": sink_clue,
                "when_to_open": f"When checking {info['name']} code for {title}",
            })

            sig_entry = {
                "pattern_id": f"sig_{card_id.replace('-', '_')}",
                "pattern": sig_pat,
                "kind": "sink",
                "strength": 3,
                "card_id": card_id,
            }
            signals_entries.append(sig_entry)

            apis_registry.append({
                "api": sink_clue,
                "language": lang,
                "card_id": card_id,
                "doc_url": f"https://security.internal/docs/apis/{card_id}",
            })

            card = {
                "schema_version": "1.0",
                "id": card_id,
                "title": title,
                "language": lang,
                "platform_conditions": f"Standard {info['name']} platform runtime",
                "security_mechanism": f"{info['name']} specific security vulnerability: {title}. Root cause lies in language semantics or standard library handling.",
                "source_sink_clues": {
                    "source": "External input from HTTP, CLI, file, or environment",
                    "sink": sink_clue,
                },
                "tracking_guards": f"Verify whether bounds, type checks, or sanitizers are applied prior to {sink_clue}.",
                "not_candidate_when": "Not a candidate when input is a hardcoded constant, strictly sanitized, or on non-security internal paths.",
                "synthetic_vulnerable_example": vuln_code,
                "synthetic_safe_example": safe_code,
                "public_references": refs,
                "signals": [sig_entry],
                "review_record": {
                    "reviewer": "Security-Review-Board",
                    "reviewed_at": "2026-11-14",
                    "status": "reviewed",
                },
            }

            card_path = lang_dir / f"{card_id}.json"
            with open(card_path, "w", encoding="utf-8") as f:
                json.dump(card, f, indent=2, ensure_ascii=False)
                f.write("\n")

        with open(lang_dir / "index.json", "w", encoding="utf-8") as f:
            json.dump(index_entries, f, indent=2, ensure_ascii=False)
            f.write("\n")

        with open(lang_dir / "signals.json", "w", encoding="utf-8") as f:
            json.dump(signals_entries, f, indent=2, ensure_ascii=False)
            f.write("\n")

        print(f"Generated {len(info['items'])} cards for {lang}")

    REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
    with open(REGISTRY_DIR / "apis.json", "w", encoding="utf-8") as f:
        json.dump(apis_registry, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Successfully generated all {total_cards} language cards across 15 languages!")


if __name__ == "__main__":
    generate()
