# 语言问题目录草案（Top15 × Top10）

> 状态：草案 v0.2（已按首轮评审修订，仍待逐语言评审）｜日期：2026-11-14
>
> 用途：给[系统设计 §7](./SYSTEM_DESIGN.md)的知识库提供首版名册与条目标题。这里只定“关注什么”，每条对应的卡片正文、信号与合成示例在实现阶段编写。
>
> 约束：条目只引用语言本身、标准库和官方平台 SDK 的公开接口，不引用第三方框架，不来自任何一次具体审计。

## 入选判据

一个条目必须同时满足：

1. **语言内生。** 根因在语言语义、类型系统、内存模型、标准库或官方运行平台的惯用法里。把同一段逻辑换一种语言写，问题会消失或换一种形态。
2. **有公开依据。** 能用公开资料支撑其普遍性（CWE、语言官方文档、公开的生态安全公告库）。
3. **后果严重。** 存在现实可达的高影响后果。
4. **可从源码审出。** 能用“不可信输入 → 缺失的守卫 → 敏感操作”的方式在源码里定位和论证。
5. **可点名。** 能写出至少 3 个语言特有的接口或语法形态。

6. **不是代码坏味道。** 忽略错误、强制解包、缺少严格模式这类条目很容易泛化。它们只在落到安全判定路径（鉴权、验签、证书校验、权限检查、输入校验）或请求可达的共享服务路径上时才算候选，其余只记加固备注。条目标题里已写明这一限定，卡片必须有“不算候选的情形”一节。

通用的 Web 逻辑问题（越权、业务逻辑缺陷等）不进目录，由统一方法覆盖；第三方框架的专属表现留给可选的生态扩展包。

名册沿用前代已批准的 15 种语言：C、C++、C#、Go、Java、Rust、Python、JavaScript、TypeScript、Kotlin、Scala、PHP、Ruby、Swift、Shell。条目编号形如 `go-03`，序号表示关注优先级。

**基座语言。** TypeScript 运行在 JavaScript 之上，Kotlin 与 Scala 运行在 Java 平台之上，C++ 沿用 C 的接口。审读这四种语言的文件时，两份索引同时适用：主语言给完整索引，基座语言给精简索引。下面各语言的条目因此不重复基座语言已有的内容。

## C

1. 越界读写：未校验的长度或下标驱动内存访问（`memcpy`、`strcpy`、`sprintf`、数组下标）
2. 整数溢出、截断与符号转换进入分配和边界计算（`size_t` 与 `int` 混用、乘法溢出后 `malloc`）
3. 释放后使用、重复释放、悬垂指针（错误路径清理、回调持有已释放对象）
4. 未初始化内存的使用与信息泄漏（栈与堆未初始化、结构体填充字节）
5. 格式化字符串由外部控制（`printf` 族、`syslog`）
6. 字符串终止与差一错误（`strncpy` 不补 NUL、对非终止缓冲调用 `strlen`）
7. 安全判定与资源路径上的返回值、错误路径未检查导致失效开放（`malloc` 返回空、`read`/`recv` 部分读、`goto cleanup`、校验函数的返回值被丢弃）
8. 文件竞态与不安全临时文件（`access` 后 `open`、`mktemp`、符号链接跟随）
9. 命令执行与环境信任（`system`、`popen`、`exec*`、`PATH` 与环境变量、特权降级顺序）
10. 未定义行为与并发、信号安全（有符号溢出使检查被优化掉、数据竞争、信号处理函数里的非异步安全调用）

## C++

1. 对象生命周期：悬垂引用、迭代器失效、`string_view` 与 `span` 悬垂、lambda 引用捕获、移动后使用
2. 异步与并发中的对象存活期和数据竞争（回调与分离线程捕获 `this`、`shared_from_this` 与 `weak_ptr` 误用、协程帧中跨 `co_await` 的悬垂引用与按引用传入的参数、非原子共享状态、重入）
3. 容器与裸缓冲越界（`operator[]` 不检查、`data()` 加长度、与 C 接口交界处）
4. 尺寸计算中的整数溢出与截断（`size_t` 与 `int` 混用、`new[]`、`reserve`、`resize`）
5. 不安全类型转换造成类型混淆（`static_cast` 向下转型、`reinterpret_cast`、C 风格转换、联合体）
6. 所有权错误（裸 `new`/`delete`、`delete` 与 `delete[]` 不匹配、`shared_ptr` 循环引用、裸指针被二次接管）
7. 异常安全与不变量破坏（异常使状态半更新、析构函数抛出、`noexcept` 触发终止）
8. 未初始化成员与不确定值（缺少成员初始化、填充字节泄漏）
9. 对非平凡类型使用 C 的内存接口（`memcpy`、`memset`、`realloc` 作用于带构造与析构语义的对象）
10. 多态与隐式转换陷阱（构造与析构期间的虚调用、经非虚析构函数做多态删除、对象切片、缺 `explicit` 的隐式转换绕过检查）

## C#

1. 不安全反序列化（`BinaryFormatter`、`NetDataContractSerializer`、`LosFormatter`、带类型解析的 JSON 与 XML 反序列化）
2. SQL 注入（ADO.NET 命令文本的字符串拼接与插值、原始 SQL 接口）
3. XML 外部实体与不安全的 XML、XSLT 处理（`XmlDocument`、`XmlTextReader` 的 DTD 处理、`XmlResolver`、XSLT 脚本）
4. 进程与动态代码执行（`Process.Start` 的参数串与 `UseShellExecute`、`Assembly.Load`、`Type.GetType` 加反射调用）
5. 路径穿越与归档解压（`Path.Combine` 遇到绝对路径会丢弃基路径、`ZipArchiveEntry.FullName`）
6. ASP.NET 请求处理陷阱（模型绑定的过度提交、授权与防伪特性缺失或被继承覆盖、开放重定向）
7. 原样 HTML 输出造成 XSS（`Html.Raw`、`MarkupString`、`HtmlString`）
8. 密码学与随机数误用（用 `System.Random` 生成令牌、ECB 与固定 IV、证书校验回调恒返回真、非常量时间比较）
9. `unsafe`、P/Invoke、`Span`、`Marshal` 的内存安全边界（外部长度的 `stackalloc`、`Marshal.Copy`、结构体布局）
10. 资源耗尽与异步陷阱（`Regex` 不设超时、请求体与集合无上限、`async void` 的未观察异常、默认 `unchecked` 的整数溢出）

## Go

1. 数据竞争与未同步的共享状态（map 并发写、闭包捕获循环变量、先检查后操作）
2. 安全判定路径上的错误值被忽略或遮蔽导致失效开放（鉴权、验签、证书校验、权限检查处未检查 `err`、`:=` 遮蔽、把零值当有效结果）
3. 请求可达路径上由不可信输入触发的 panic（nil 解引用、写 nil map、切片越界、不带 `ok` 的类型断言、共享服务缺 `recover`）
4. 整数转换与溢出（`strconv.Atoi` 结果转 `int32`/`int16` 截断、`len` 运算、有无符号混用）
5. 无界资源消耗（`io.ReadAll` 读请求体、`http.Server` 不设超时、缺 `http.MaxBytesReader`、goroutine 泄漏、按外部长度 `make`）
6. 命令、模板与 SQL 注入（`os/exec` 经 `sh -c` 或参数注入、用 `text/template` 输出 HTML、`template.HTML` 强转、`fmt.Sprintf` 拼 SQL）
7. 路径穿越、归档与符号链接（`filepath.Join` 不约束根目录、`http.Dir`、`archive/zip` 与 `archive/tar` 的条目名）
8. `unsafe`、cgo、`reflect` 边界（指针运算、`unsafe.Slice`/`unsafe.String` 的生命周期、cgo 缓冲长度、把 Go 指针传给 C）
9. 密码学与 TLS 误用（用 `math/rand` 生成密钥或令牌、`InsecureSkipVerify`、缺 `subtle.ConstantTimeCompare`、AEAD nonce 重用）
10. 解码与解析语义差异（`encoding/json` 字段名大小写不敏感、重复键后者覆盖、未知字段被忽略、`interface{}` 数值精度；`net/url` 与 HTTP 头解析差异、默认跟随重定向）

## Java

1. 不安全反序列化（`ObjectInputStream.readObject`、`XMLDecoder`、带多态类型的 JSON 与 YAML 绑定）
2. 表达式与命名查找注入（JNDI `InitialContext.lookup`、表达式语言、`ScriptEngine.eval`）
3. XML 外部实体（`DocumentBuilderFactory`、`SAXParserFactory`、`XMLInputFactory`、`TransformerFactory` 的默认配置）
4. SQL 与 JPQL 注入（`Statement` 拼接、`createQuery`/`createNativeQuery` 的字符串拼接）
5. 路径穿越与归档解压（`new File(base, input)`、`Paths.get`、`ZipEntry.getName`、缺规范化后的前缀校验）
6. 命令执行、不安全反射与类加载（`Runtime.exec`、`ProcessBuilder`、`Class.forName`、`URLClassLoader`、`Method.invoke`）
7. 单例与共享组件里的并发和可变状态（Servlet 实例字段、非线程安全的 `SimpleDateFormat` 与 `HashMap`、先检查后操作）
8. 影响安全判定的数值与接口契约陷阱（整数静默回绕、`int` 与 `long` 混用、`String.split` 丢弃尾随空串、装箱类型用 `==` 比较、安全检查处吞异常导致失效开放）
9. 密码学、随机数与 TLS 误用（`java.util.Random`、`Cipher.getInstance("AES")` 默认 ECB、固定 IV、全信任的 `TrustManager` 与 `HostnameVerifier`、不用 `MessageDigest.isEqual` 比较）
10. Servlet 与 URL 处理差异（路径规范化与匹配不一致、`URL` 与 `URI` 解析不一致、`URL.openConnection` 支持多种协议、重定向与请求转发）

## Rust

1. `unsafe` 块的健全性（裸指针解引用、`slice::from_raw_parts` 的长度、`transmute`、`MaybeUninit::assume_init`、`get_unchecked`、`Vec::set_len`）
2. FFI 边界（`extern "C"`、`CStr`/`CString` 的生命周期、`Box::from_raw` 重复释放、`repr(C)` 布局不符、panic 穿过 FFI）
3. 请求可达路径上由不可信输入触发的 panic（`unwrap`、`expect`、下标与切片越界、`RefCell` 重复借用、除零、递归栈溢出）
4. 整数溢出回绕与有损的 `as` 转换（release 构建下回绕，截断或符号变化进入长度、下标、分配）
5. 不健全的 `Send`/`Sync` 与并发缺陷（手写 `unsafe impl`、`static mut`、原子操作的内存序错误、锁中毒与死锁、跨 `.await` 的状态竞态）
6. 无界资源消耗（按外部长度 `Vec::with_capacity`、`read_to_end`、无界通道与任务、解压炸弹、异步取消留下不一致状态）
7. 反序列化与解析信任（长度前缀驱动分配、不拒绝未知字段、无标签枚举的歧义、深层嵌套递归）
8. 命令与路径注入（`std::process::Command` 经 shell 或参数注入、`Path::join`/`PathBuf::push` 遇绝对路径会替换基路径、归档条目路径）
9. 密码学与秘密处理（用 `==` 比较 MAC、随机源误用、nonce 重用、秘密未清零、关闭证书校验）
10. 建立在 `unsafe` 上的安全抽象的生命周期、别名与 panic 安全（`ptr::read` 造成重复 drop、依赖析构一定执行、`Pin` 误用、panic 时不变量被破坏）

## Python

1. 不安全反序列化（`pickle`、`marshal`、`shelve`、使用非安全加载器的 YAML、允许 pickle 的数据与模型加载接口）
2. 代码与表达式注入（`eval`、`exec`、`compile`、`__import__` 与 `importlib`、`str.format` 的属性遍历、由输入构造模板）
3. 命令注入（`subprocess` 的 `shell=True`、`os.system`、`os.popen`、参数注入）
4. 路径穿越与归档解压（`os.path.join` 遇绝对分量会丢弃基路径、`tarfile.extractall`、`zipfile`、`tempfile.mktemp` 竞态）
5. SQL 注入（DB-API `cursor.execute` 里的字符串格式化与 f-string 拼接）
6. XML 与正则解析危害（`xml.etree`、`xml.sax`、`xml.dom` 的实体膨胀与外部实体，`re` 的灾难性回溯）
7. 动态类型与真值语义造成的检查绕过（`==` 与 `is`、`None` 与空值的真值、JSON 类型混淆、`assert` 被 `-O` 移除、可变默认参数共享状态）
8. 外联请求与 URL 处理（`urllib` 的多协议与重定向、`ssl` 关闭校验、`urllib.parse` 的解析差异）
9. 密码学与随机数误用（应使用 `secrets` 却用 `random`、用 `hashlib` 的快速散列存口令、应使用 `hmac.compare_digest` 却用 `==`）
10. 原生扩展与资源边界（`ctypes` 与 `struct` 的长度处理、不带上限的 `read()`、解压炸弹、大整数与字符串互转、递归深度）

## JavaScript

1. 原型污染（递归合并与按路径赋值接受 `__proto__`、`constructor.prototype`）
2. 代码注入（`eval`、`new Function`、字符串形式的 `setTimeout`、把 `vm` 模块当沙箱、动态 `require` 与 `import()`）
3. 命令注入（`child_process.exec`、`execSync`、`spawn` 的 `shell: true`、参数注入）
4. DOM XSS 与不安全的 HTML 接收点（`innerHTML`、`outerHTML`、`document.write`、`insertAdjacentHTML`、`javascript:` URL、不校验来源的 `postMessage`）
5. 类型强制与宽松比较（`==`、查询串与请求体解析出数组或对象代替字符串、`parseInt` 的怪癖、超过 2^53 的数值精度）
6. 路径穿越与文件服务（`path.join`、`path.resolve` 处理外部输入，`fs` 直接使用用户路径，归档条目）
7. 正则回溯与事件循环阻塞（灾难性回溯、同步重操作、按外部长度 `Buffer.alloc`、`Buffer.allocUnsafe` 泄漏未初始化内存）
8. 异步与错误处理缺陷（未处理的 Promise 拒绝使进程退出、鉴权检查漏写 `await`、跨 `await` 的竞态、吞错导致失效开放）
9. 不安全的反序列化与解析（基于 `eval` 的序列化、`JSON.parse` 的 reviver 误用、会展开实体的 XML 解析）
10. 密码学、随机数与 TLS 误用（用 `Math.random` 生成令牌、不用 `crypto.timingSafeEqual` 比较、`rejectUnauthorized: false`、已弃用的弱加密接口）

## TypeScript

1. 类型擦除：把编译期类型当作运行时保证（对外部 JSON 或请求体做 `as T` 断言，没有运行时校验）
2. 在安全边界上使用类型系统逃生口（`any`、`as unknown as T` 双重断言、非空断言 `!`、`@ts-ignore`）
3. 不健全的收窄与结构化类型（写错的自定义类型守卫 `x is T`、判别字段受攻击者控制的可辨识联合、展开运算符夹带多余属性造成批量赋值）
4. 索引签名与原型污染（`Record<string, T>` 与 `obj[key]` 使用外部键、关闭 `noUncheckedIndexedAccess` 后的 `undefined` 传播）
5. 枚举与字面量陷阱（数值枚举接受任意数字、`const enum` 被擦除、字符串联合没有运行时校验导致角色或状态混淆）
6. 装饰器与元数据驱动的校验缺口（校验只在装饰器里声明而运行时未启用、反射元数据缺失时静默放行）
7. Promise 类型陷阱（浮动 Promise 使校验或鉴权未被等待、把 `Promise<boolean>` 直接用于条件判断、`catch (e: any)` 吞错）
8. 编译配置造成的保证缺口（关闭 `strict` 或 `strictNullChecks`、`skipLibCheck`、声明文件与运行时行为不符、路径别名解析到非预期模块）
9. 仅在编译期生效的访问控制与不可变性（`private`、`readonly` 在运行时不生效，与 `#private` 的差别，类实例反序列化后丢失不变量）
10. 序列化边界上的数值、日期与大整数（`JSON.parse` 返回 `any`、64 位 ID 精度丢失、`bigint` 与 `Date` 往返失真）

## Kotlin

1. Java 互操作的空安全缺口使校验被绕过或进程崩溃（平台类型的空值流入安全判定、不可信输入路径上的 `!!`、访问未初始化的 `lateinit`）
2. Android 组件暴露与 Intent 处理（导出组件、隐式 Intent、Intent 重定向、可变的 `PendingIntent`、深链参数校验）
3. 不安全反序列化与类型混淆（`getSerializableExtra`、`getParcelableExtra`、绕过构造器的反射式绑定使非空字段为 null）
4. WebView 误用（`addJavascriptInterface`、`setJavaScriptEnabled`、文件访问开关、加载不可信 URL）
5. 协程并发（跨挂起点的先检查后操作、没有 `Mutex` 或线程约束的共享可变状态、`GlobalScope` 泄漏、`launch` 与 `async` 的异常被吞）
6. SQL 注入与 ContentProvider 路径穿越（`rawQuery`、`execSQL` 里的字符串模板，`openFile` 使用 `uri.lastPathSegment`）
7. 字符串模板注入（用模板拼接命令传给 `Runtime.exec` 或 `ProcessBuilder`、脚本引擎 `eval`、反射 `callBy`）
8. 不安全存储与密码学（`SharedPreferences` 明文存秘密、外部存储、硬编码密钥、`Cipher.getInstance("AES")` 默认 ECB、Keystore 误用）
9. 网络信任（全信任的 `TrustManager` 与 `HostnameVerifier`、明文流量、证书固定被绕过）
10. 影响安全逻辑的 Kotlin 语义陷阱（可变 `var` 上的智能转换竞态、`data class` 的 `copy()` 绕过构造校验、`when` 的缺省分支失效开放、`runCatching { }.getOrNull()` 与 `?:` 吞掉鉴权错误、`object` 单例的可变状态）

## Scala

1. 不安全反序列化（Java 序列化 `ObjectInputStream`、默认使用 Java 序列化的远程消息传输、带多态类型的 JSON 绑定）
2. 代码与命令注入（运行时反射 `ToolBox.eval`、`scala.sys.process` 的字符串命令、用字符串插值器拼接命令）
3. 插值器造成的 SQL 注入（`s"..."` 拼接查询、SQL 插值器里的原样拼接片段）
4. 隐式转换与 `given` 解析改变安全语义（隐式转换隐藏不安全变换、选错隐式执行上下文、通用相等比较不同类型时恒为假）
5. 模式匹配非穷尽与偏函数（`MatchError`、缺省分支失效开放、`Option.get`、`head`、`Try.get`、Java 互操作的 `null` 绕过 `Option`）
6. `Future` 与 Actor 并发（闭包捕获 `var` 或可变集合、Actor 状态经闭包逃逸、阻塞默认调度器造成饥饿、`lazy val` 初始化死锁）
7. XML 处理（`scala.xml.XML.load` 的外部实体、XML 字面量里未转义的插值）
8. 流与集合的资源耗尽（`LazyList` 记忆化无界增长、没有背压或帧长上限的流处理、无界邮箱、`.r` 正则回溯）
9. 路径与 URL 处理（`scala.io.Source.fromURL`、`fromFile` 接受外部输入且支持 `file:`，归档条目）
10. 密码学、随机数与秘密泄漏（用 `scala.util.Random` 生成令牌、非常量时间比较、`case class` 自动生成的 `toString` 暴露秘密字段）

## PHP

1. 类型戏法与宽松比较（`==`、`!=`、非严格的 `in_array` 与 `array_search`、给 `strcmp` 传数组、`"0e"` 魔术散列、`switch` 的宽松匹配）
2. 对象注入（`unserialize()` 与魔术方法链、`phar://` 元数据经文件函数触发反序列化）
3. 文件包含与流包装器（`include`、`require` 使用外部输入，`php://filter`、`data://`，`allow_url_fopen` 下的 `file_get_contents`、`fopen`，`move_uploaded_file` 不限制类型）
4. 代码与命令注入（`eval`、动态函数调用 `$fn()` 与 `call_user_func`、可变变量 `$$`、`system`、`exec`、`shell_exec`、`passthru`、`proc_open`、反引号、`mail()` 的附加参数）
5. SQL 注入（`mysqli_query`、`PDO::query` 里的字符串插值，模拟预处理的陷阱，标识符与 `ORDER BY` 拼接）
6. 请求变量注入（`extract()`、不带目标数组的 `parse_str()`、`$_REQUEST` 的优先级、`a[]=` 数组参数造成类型混淆、信任 `$_FILES`）
7. 输出编码与响应注入（未转义的 `echo`、`htmlspecialchars` 的标志与字符集误用、`header()` 注入与开放重定向）
8. 会话、认证与密码学误用（应使用 `password_hash` 却用 `md5`、`sha1`，应使用 `random_bytes` 却用 `rand`、`mt_rand`、`uniqid`，不用 `hash_equals` 比较，缺 `session_regenerate_id`）
9. XML 与外联解析（`LIBXML_NOENT` 引入外部实体、`simplexml_load_string`、`SoapClient` 拉取 WSDL、`curl` 的多协议与重定向）
10. 运行时怪癖导致失效开放（`strpos` 的 `false` 与 `0` 混淆、`@` 抑制错误后继续执行、`intval` 与 `(int)` 的部分解析、`is_numeric` 的怪癖、`preg_match` 里 `$` 匹配尾随换行以及触达回溯上限时返回 `false`）

## Ruby

1. 不安全反序列化（`Marshal.load`、非安全的 `YAML.load`、`JSON` 的 `create_additions`）
2. 动态执行与元编程（`eval`、`instance_eval`、`class_eval`、方法名受控的 `send` 与 `public_send`、`const_get`、由输入构造 ERB 模板）
3. 命令注入（`system`、`exec`、反引号、`%x`、`IO.popen`、`Open3` 的字符串插值，`Kernel#open` 与 `IO.read` 遇前导 `|` 会执行命令）
4. SQL 注入（数据库驱动与查询接口里的 `#{}` 字符串插值，排序、列名、片段的原样拼接）
5. 参数类型混淆与批量赋值（期望 String 却得到 Hash 或 Array，嵌套参数直接用于属性更新或查询条件）
6. 正则锚点与字符串语义（`^`、`$` 按行匹配，应使用 `\A`、`\z`；正则回溯与 `Regexp.timeout`；对外部输入调用 `to_sym`）
7. 输出安全标记误用（把字符串标记为安全或原样输出的接口，HTML 属性与 `javascript:` URL 未转义）
8. 路径与文件处理（`File.join`、`File.read` 的穿越，`Pathname#join` 遇绝对路径会覆盖基路径，`Dir.glob` 注入，归档解压，可预测的临时文件）
9. 开放类与可见性绕过（猴子补丁改变校验语义、`method_missing` 与 `respond_to_missing?` 暴露非预期方法、`send` 绕过 `private`、类级可变状态在多线程下跨请求泄漏）
10. 密码学、随机数与中断安全（应使用 `SecureRandom` 却用 `rand`、`Random`，非常量时间比较，`Timeout.timeout` 的异步中断留下不一致状态）

## Swift

1. 不安全指针与手工内存管理（`UnsafeMutablePointer`、`UnsafeRawBufferPointer`、`withUnsafeBytes` 的指针逃逸、`bindMemory` 与 `assumingMemoryBound`、`Unmanaged` 的保留与释放失衡）
2. Objective-C 与 C 互操作边界（`NSKeyedUnarchiver` 未启用安全编码、`as!` 桥接类型混淆、KVC `setValue(_:forKeyPath:)` 使用外部键、`NSPredicate(format:)` 与 `NSExpression` 注入、`String(format:)` 使用外部格式串）
3. 不可信输入可达路径上的运行时陷阱造成拒绝服务（强制解包 `!`、`try!`、`as!`、数组越界、算术溢出陷阱、`unowned` 悬垂访问、`fatalError` 与 `precondition`）
4. 并发与数据竞争（跨队列或 Task 的共享可变状态、`@unchecked Sendable`、`nonisolated(unsafe)`、actor 重入造成跨 `await` 的先检查后操作）
5. 进程、脚本与 URL 入口注入（`Process` 经 shell、`NSAppleScript`、自定义 URL scheme 与通用链接的参数、`WKWebView.evaluateJavaScript` 的字符串拼接、对脚本消息桥的信任）
6. 不安全存储、密码学与传输信任（用 `UserDefaults` 或 plist 存秘密、Keychain 可访问性级别、CommonCrypto 的 ECB、固定 IV 与缓冲区大小、`URLSessionDelegate` 接受任意证书、ATS 例外）
7. 路径与文件处理（`appendingPathComponent` 使用不可信名称、符号链接跟随、归档条目路径、可预测的临时文件、安全作用域书签与沙箱容器边界）
8. 解码与类型强制（对 `JSONSerialization` 返回的 `Any` 做 `as?` 链、`NSNumber` 与 `Bool` 桥接、宽松的自定义 `init(from:)`、原始值枚举初始化失败后的默认回退）
9. 字符串、Unicode 与整数转换语义（`count`、`utf8.count`、`NSString.length` 不一致，`NSRange` 与 `Range<String.Index>` 混用，规范等价比较造成标识冲突，`Int(truncatingIfNeeded:)` 截断与 `Int(_:)` 陷阱）
10. 网络缓冲与服务端处理（按外部长度读取或分配 `Data` 与缓冲区、请求体不设上限、阻塞事件循环、原始 SQL 的字符串插值）

## Shell

1. 未加引号的展开（分词与路径名通配：`$var`、`$(cmd)`、`${arr[*]}`）
2. 代码注入（`eval`、`sh -c "$x"`、`source` 不可信文件、间接展开 `${!var}`、算术上下文对变量名求值、`trap` 字符串；把取回的内容直接交给解释器：`curl … | sh`、`eval "$(curl …)"`）
3. 选项与通配符注入（以 `-` 开头的文件名或输入、缺 `--`、通配符展开成选项、`xargs` 不带 `-0`）
4. 不安全临时文件与竞态（可预测的 `/tmp/name.$$`、不用 `mktemp`、特权脚本跟随符号链接、`[ -f ]` 之后再操作）
5. `PATH` 与环境信任（特权上下文里的相对命令名、`IFS`、`BASH_ENV`、`ENV`、`LD_PRELOAD`、继承的函数、`PS4` 里的命令替换）
6. 安全相关步骤的错误处理缺失导致失效开放（验签、校验和、权限设置失败后继续执行；没有 `set -euo pipefail` 或误解其语义、`local x=$(cmd)` 掩盖退出码、不检查 `cd`、管道隐藏失败、`|| true`）
7. 变量作用域、属性与名字引用污染（函数内缺 `local` 改写全局、`declare -n` 名字引用指向外部给出的名字、`declare "$name=$value"` 与 `printf -v`/`read` 写入受控变量名、`export` 与 `export -f` 泄漏到子进程、对 `readonly` 的错误假设）
8. 秘密经 shell 机制泄漏（命令行参数在进程列表可见、`set -x` 与 `PS4` 跟踪、`export` 传给所有子进程、here-doc 与 here-string 的临时文件）
9. 不可信路径上的破坏性文件操作（变量为空时的 `rm -rf "$DIR/"*`、缺 `${var:?}`、`tar` 与 `unzip` 解压穿越、递归 `chown`/`chmod` 跟随符号链接、含换行的文件名破坏循环）
10. 向其他解释器或远端注入（`ssh host "cmd $x"` 的二次求值、`sed` 与 `awk` 程序注入、定界符未加引号的 here-doc、把输入拼进 SQL、JSON 或 `python -c`）

## 评审时请关注

- 每种语言的 10 条是否都通过“换一种语言就变形或消失”的检验。
- 是否有某条实际上只是通用弱点的换名（这正是前代知识库的主要问题）。
- Kotlin 与 Swift 目前偏向官方移动平台 SDK；如果希望兼顾服务端用法，需要调整若干条目。
- 条目序号是关注优先级的初始判断，没有数据支撑。首轮评审把 C++ 的异步生命周期提到了第 2 位；各语言的排序最终应由 150 格评测和留出评测的结果校正。
