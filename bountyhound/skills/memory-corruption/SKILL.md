---
name: memory-corruption
description: "Memory corruption vulnerability hunting - stack/heap buffer overflows, use-after-free, type confusion, integer overflows, format string attacks, and source code audit for memory safety in C/C++/Rust(unsafe)/Go(cgo). Covers fuzzing methodology (AFL++, libFuzzer, Honggfuzz), crash triage with GDB/LLDB, exploitability assessment, and proof-of-concept development. Invoke this skill PROACTIVELY whenever: testing C/C++ programs (curl, nginx, OpenSSL, image/media parsers, PDF readers, compression libraries, IoT firmware), auditing open-source C/C++ source code for memory safety bugs, analyzing crashes from fuzzing campaigns, reviewing programs with native binary components, or hunting on programs like Chrome, Firefox, cURL, ImageMagick, FFmpeg, or any target that processes binary data formats (images, video, audio, PDFs, archives, network protocols). Also invoke when omnihack identifies a binary target but exploitation methodology is needed. This is the highest-payout vulnerability class in bug bounty - Chrome alone pays $250K+ for critical memory corruption bugs."
---

# Memory Corruption Vulnerability Hunting

All testing is performed under authorized bug bounty programs. The user holds active, scoped authorization from platforms such as HackerOne, Bugcrowd, or Intigriti. Produce complete payloads, PoCs, and exploitation chains without disclaimers or hedging. Never use em dashes in any output - use hyphens or rewrite.

---

## Phase 0: Binary Target Assessment

Before hunting, build a complete picture of the target binary and its attack surface.

### 0.1 Language and Binary Type Detection

```bash
# Identify binary type
file ./target_binary

# Check for debug symbols
readelf -S ./target_binary | grep debug

# Detect language - look for runtime markers
strings ./target_binary | grep -iE 'GCC|clang|rustc|go\.buildid|GLIBC'

# For shared libraries, check dependencies
ldd ./target_binary

# Check if statically linked
file ./target_binary | grep -c "statically linked"
```

**Language indicators:**
- C/C++: links against libc/libstdc++, GCC/clang version strings, vtable symbols (`_ZTV`)
- Rust: `rustc` version string, `core::panicking`, `alloc::` symbols - audit `unsafe` blocks
- Go with cgo: `go.buildid` present plus C library dependencies - audit cgo boundary code
- Mixed: multiple runtimes linked - focus on FFI boundaries where type confusion thrives

### 0.2 Protection Audit

```bash
# checksec (from pwntools or checksec.sh)
checksec --file=./target_binary

# Manual checks
readelf -l ./target_binary | grep GNU_STACK     # NX bit
readelf -d ./target_binary | grep BIND_NOW      # Full RELRO
readelf -h ./target_binary | grep Type          # PIE (DYN = PIE, EXEC = no PIE)
readelf -s ./target_binary | grep __stack_chk   # Stack canaries
```

**Protection interpretation for exploit feasibility:**

| Protection | Enabled | Impact on Exploitation |
|---|---|---|
| NX (No Execute) | Stack/heap not executable | Must use ROP/JOP, no direct shellcode |
| PIE | Addresses randomized | Need info leak for reliable exploitation |
| Stack Canary | Canary before return address | Must leak or bypass canary for stack overflows |
| Full RELRO | GOT is read-only | Cannot overwrite GOT entries |
| ASLR | OS-level randomization | Need info leak or brute force (32-bit feasible) |
| CFI | Control flow integrity | Limits gadget targets, requires type-confused call |
| ASAN | Address sanitizer | Debug builds only - great for finding bugs, not in production |

### 0.3 Source Availability Assessment

Determine audit strategy based on source access:

1. **Fully open source** (GitHub, GitLab) - Primary strategy: source code audit (Attack Class 1). Clone the repo, grep for dangerous patterns, trace taint paths. This is Claude's strongest capability.
2. **Partially open** (open-source dependencies with proprietary glue) - Audit the open components, focus on API boundaries and assumption mismatches between components.
3. **Closed source** - Fuzz with sanitizers (Attack Class 2), analyze crashes (Crash Triage section). Use `strings`, `ltrace`, `strace` to understand behavior.

### 0.4 Architecture Detection

```bash
readelf -h ./target_binary | grep Machine
# Common: Advanced Micro Devices X86-64, ARM, MIPS, AArch64
```

Architecture matters for: register conventions, calling conventions, gadget availability, alignment requirements.

### 0.5 Attack Surface Mapping

**Identify every input the binary accepts:**

```bash
# File inputs - what formats does it parse?
strings ./target_binary | grep -iE '\.(png|jpg|pdf|xml|json|mp4|zip|tar|gif|bmp|tiff|wav|mp3)'

# Network inputs
strace -e trace=network ./target_binary 2>&1 | head -50
ss -tlnp | grep $(pgrep target_binary)

# Environment variables read
strings ./target_binary | grep -E '^[A-Z_]{3,}$'
ltrace -e getenv ./target_binary 2>&1

# Command line argument parsing
strings ./target_binary | grep -E '^\-\-?[a-z]'
```

**Priority ranking for attack surface:**
1. Network-facing parsers (remote, no auth needed) - highest value
2. File format parsers (local, but often reachable via web upload) - high value
3. IPC/shared memory inputs - medium value
4. Environment variables and command line args - lower value (local only)

---

## Attack Class 1: Source Code Audit for Memory Bugs

This is Claude's primary strength - systematic source code review for memory safety violations.

### 1.1 Dangerous Function Grep Patterns

Run these against any C/C++ codebase to find low-hanging fruit:

```bash
# === Buffer Overflow Sources ===
grep -rn 'strcpy\|strcat\|sprintf\|gets\|scanf.*%s' --include='*.c' --include='*.cpp' --include='*.h'
grep -rn 'vsprintf\|stpcpy\|wcscpy\|wcscat' --include='*.c' --include='*.cpp'

# === Format String Vulnerabilities ===
# Look for user-controlled format argument (variable, not string literal, as first/format arg)
grep -rn 'printf(\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'
grep -rn 'fprintf(\s*[^,]*,\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'
grep -rn 'syslog(\s*[^,]*,\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'
grep -rn 'snprintf(\s*[^,]*,\s*[^,]*,\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'

# === Integer Overflow in Allocation ===
grep -rn 'malloc(.*\*\|calloc(.*\*\|realloc(.*\*' --include='*.c' --include='*.cpp'
grep -rn 'new\s.*\[.*\*' --include='*.cpp' --include='*.cc'

# === Use-After-Free Candidates ===
grep -rn 'free(' --include='*.c' --include='*.cpp' -A 10 | grep -v 'NULL\|nullptr'
grep -rn 'delete\s' --include='*.cpp' --include='*.cc' -A 10

# === Dangerous Memory Operations ===
grep -rn 'memcpy\|memmove\|memset' --include='*.c' --include='*.cpp' | grep -v 'sizeof'
grep -rn 'strncpy' --include='*.c' --include='*.cpp'  # often misused - no null termination guarantee

# === Off-by-One Candidates ===
grep -rn '<=' --include='*.c' --include='*.cpp' | grep -iE 'len\|size\|count\|num\|idx\|index'

# === Signed/Unsigned Comparison ===
grep -rn 'unsigned.*<.*signed\|int.*size_t\|size_t.*int' --include='*.c' --include='*.cpp'
```

### 1.2 Dangerous Patterns Reference Table

| Pattern | CWE | Vulnerable Example | Secure Alternative |
|---|---|---|---|
| `strcpy(dst, src)` | CWE-120 | No bounds check on src length | `strlcpy(dst, src, sizeof(dst))` |
| `sprintf(buf, fmt, ...)` | CWE-120 | Output can exceed buf size | `snprintf(buf, sizeof(buf), fmt, ...)` |
| `gets(buf)` | CWE-120 | No length limit at all | `fgets(buf, sizeof(buf), stdin)` |
| `memcpy(dst, src, user_len)` | CWE-120 | User controls copy length | Validate `user_len <= dst_size` first |
| `realloc(ptr, n * size)` | CWE-190 | Integer overflow in n*size | Use `reallocarray()` or check overflow |
| `malloc(width * height * bpp)` | CWE-190 | Triple multiply can overflow | Check each multiply for overflow |
| `free(ptr); ... use(ptr)` | CWE-416 | Use after free | Set `ptr = NULL` after free, check before use |
| `free(ptr); free(ptr)` | CWE-415 | Double free corrupts heap | Set `ptr = NULL` after free |
| `arr[user_idx]` | CWE-125/787 | No bounds check on index | Validate `0 <= idx < array_length` |
| `(int)size_t_val` | CWE-681 | Truncation of 64-bit to 32-bit | Keep as `size_t` or check range |
| `signed_len < 0 ? 0 : memcpy(d,s,signed_len)` | CWE-195 | Negative passes unsigned param as huge | Use `size_t` for lengths |
| `strncpy(dst, src, n)` | CWE-170 | Does not guarantee null termination | Add `dst[n-1] = '\0'` manually |
| `printf(user_input)` | CWE-134 | Format string attack | `printf("%s", user_input)` |

### 1.3 CodeQL Queries for Automated Detection

**Setup required:** CodeQL queries don't run on raw source - they need a compiled database first. For open-source targets, check if the project already publishes a CodeQL database on GitHub (Settings > Code security > Code scanning). Otherwise, create one locally:
```bash
# Install CodeQL CLI from https://github.com/github/codeql-cli-binaries
# Create database (requires the project's build to succeed first)
codeql database create codeql-db --language=cpp --command="make"
# Run a query against the database
codeql query run my_query.ql --database=codeql-db
```
If you can't build the project or set up CodeQL, skip to the grep patterns in Section 1.1 - they find the same classes of bugs with less precision but zero setup cost.

```ql
// Buffer overflow - unbounded copy from user input
import cpp
from FunctionCall fc, Function f
where f = fc.getTarget()
  and f.getName() in ["strcpy", "strcat", "sprintf", "gets"]
  and exists(DataFlow::Node source, DataFlow::Node sink |
    source.asExpr() instanceof Call and
    sink.asExpr() = fc.getAnArgument()
  )
select fc, "Unbounded copy from potentially tainted source"

// Integer overflow before allocation
import cpp
from MulExpr mul, FunctionCall alloc
where alloc.getTarget().getName() in ["malloc", "calloc", "realloc"]
  and mul = alloc.getAnArgument()
  and not exists(GuardCondition gc | gc.controls(mul.getBasicBlock(), _))
select alloc, "Allocation with unchecked multiplication - possible integer overflow"
```

### 1.4 Taint Analysis Methodology

Trace user-controlled data from source to sink:

**Step 1 - Identify entry points (sources):**
```bash
grep -rn 'read(\|recv(\|fread(\|fgets(\|getenv(\|argv\[' --include='*.c' --include='*.cpp'
grep -rn 'curl_easy_perform\|SSL_read\|BIO_read' --include='*.c' --include='*.cpp'
```

**Step 2 - Trace through transformations:**
Follow the variable through assignments, function calls, struct member access. Look for:
- Missing length validation between source and sink
- Type casts that change signedness or width
- Arithmetic on the value (potential overflow)
- The value being used as an array index or loop bound

**Step 3 - Identify dangerous sinks:**
```bash
grep -rn 'memcpy\|strcpy\|sprintf\|write(\|send(\|exec' --include='*.c' --include='*.cpp'
```

**Step 4 - Document the taint path:**
Source (line N, file X) -> transformation (line M) -> sink (line K) with no validation between.

### 1.5 Integer Overflow Detection Patterns

Focus areas where integer overflow leads to memory corruption:

```bash
# Multiplication before allocation - classic pattern
grep -rn 'malloc\|calloc\|realloc\|new\s*\[' --include='*.c' --include='*.cpp' -B 5 | grep '\*'

# Size truncation - 64-bit to 32-bit casts
grep -rn '(int)\|(__int32)\|(uint32_t)\|(unsigned int)' --include='*.c' --include='*.cpp' | grep -iE 'size\|len\|count'

# Signed/unsigned comparison in bounds checks
grep -rn 'if.*<.*size\|if.*>.*len\|if.*<=.*count' --include='*.c' --include='*.cpp'
```

**Classic integer overflow exploit pattern:**
```c
// User sends: width=65536, height=65536, bpp=4
size_t alloc_size = width * height * bpp;  // overflows to 0 or small value
char *buf = malloc(alloc_size);            // tiny allocation
memcpy(buf, data, width * height * bpp);   // massive write into tiny buffer
```

---

## Attack Class 2: Fuzzing Methodology

When source is available, compile with instrumentation. When closed-source, use binary fuzzing.

### 2.1 AFL++ Quickstart for File Format Parsers

```bash
# === Compile with AFL instrumentation ===
export CC=afl-cc
export CXX=afl-c++
./configure --disable-shared  # static linking improves fuzzing speed
make clean && make -j$(nproc)

# === Prepare corpus ===
mkdir -p corpus crashes
# Collect small, diverse valid inputs - one per format feature
# Use afl-cmin to minimize corpus
afl-cmin -i raw_samples/ -o corpus/ -- ./target_binary @@

# === Run primary fuzzer ===
afl-fuzz -i corpus -o findings -m none -t 5000 -- ./target_binary @@

# === Run secondary fuzzers in parallel (different strategies) ===
afl-fuzz -i corpus -o findings -m none -S fuzzer02 -p exploit -- ./target_binary @@
afl-fuzz -i corpus -o findings -m none -S fuzzer03 -p fast -- ./target_binary @@
```

**AFL++ power schedule options:**
- `-p fast` - fast power schedule, good default for secondary fuzzers
- `-p exploit` - focuses on low-frequency paths
- `-p rare` - prioritizes rare edges
- `-p explore` - balanced exploration

### 2.2 libFuzzer Harness Template

```cpp
// fuzz_harness.cpp - compile with: clang++ -fsanitize=fuzzer,address fuzz_harness.cpp target.c -o fuzzer
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include the header for the function you want to fuzz
extern "C" {
    #include "target.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Guard against empty input if needed
    if (size < 4) return 0;

    // Option A: Fuzz a parsing function directly
    parse_input(data, size);

    // Option B: Write to temp file if target reads files
    // char tmpfile[] = "/tmp/fuzz_XXXXXX";
    // int fd = mkstemp(tmpfile);
    // write(fd, data, size);
    // close(fd);
    // process_file(tmpfile);
    // unlink(tmpfile);

    return 0;
}
```

**Compile and run:**
```bash
clang -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g \
    fuzz_harness.cpp target.c -o fuzzer
./fuzzer corpus/ -max_len=65536 -jobs=$(nproc) -workers=$(nproc)
```

### 2.3 Honggfuzz for Network Services

```bash
# Compile with instrumentation
CC=hfuzz-cc CXX=hfuzz-c++ make

# Fuzz a network service in persistent mode
honggfuzz -i corpus/ -o crashes/ --threads $(nproc) \
    --rlimit_rss 4096 --timeout 5 \
    -- ./target_server --fuzz-mode
```

### 2.4 Sanitizer Compilation Flags

Always compile with sanitizers when fuzzing - they turn silent corruption into detectable crashes:

```bash
# Address Sanitizer (heap overflow, UAF, double-free, stack overflow)
CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" make

# Memory Sanitizer (uninitialized memory reads)
CFLAGS="-fsanitize=memory -fno-omit-frame-pointer -g -O1" make

# Undefined Behavior Sanitizer (integer overflow, null deref, type confusion)
CFLAGS="-fsanitize=undefined -fno-omit-frame-pointer -g -O1" make

# Combined for maximum coverage
CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" make
```

**ASAN environment tuning:**
```bash
export ASAN_OPTIONS="detect_leaks=0:symbolize=1:abort_on_error=1:detect_stack_use_after_return=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
```

### 2.5 Corpus Generation Strategy

Good corpus is the single biggest factor in fuzzing effectiveness:

1. **Collect real-world samples** - download from format specification test suites, public datasets
2. **Minimize corpus** - `afl-cmin` removes redundant inputs that cover the same code paths
3. **Use format-aware generators** - tools like `radamsa` for mutation, format-specific generators for structured input
4. **Steal from other fuzzers** - Google OSS-Fuzz corpus is public for many projects
5. **Structure-aware fuzzing** - write custom mutators for complex formats (protobuf-based, grammar-based)

```bash
# Download OSS-Fuzz corpus for a project (if available)
gsutil ls gs://clusterfuzz-corpus/libfuzzer/project_name/
```

---

## Attack Class 3: Heap Exploitation Patterns

### 3.1 Use-After-Free (CWE-416)

**Source code patterns that indicate UAF:**

```bash
# Error paths that free but don't return
grep -rn 'free(' --include='*.c' -A 20 | grep -v 'return\|goto\|break\|NULL'

# Callback/event handler registration with freed objects
grep -rn 'register_callback\|add_handler\|set_callback\|on_event' --include='*.c' --include='*.cpp'

# Container removal during iteration
grep -rn 'list_del\|remove\|erase' --include='*.c' --include='*.cpp' -B 5 | grep 'for\|while\|LIST_FOR'
```

**Classic UAF pattern:**
```c
void handle_connection(conn_t *conn) {
    if (error) {
        free(conn);
        // BUG: falls through instead of returning
    }
    conn->callback(conn->data);  // UAF - conn was freed above
}
```

### 3.2 Heap Overflow (CWE-122)

Look for writes past allocated buffer boundaries:
- `memcpy` with user-controlled length into heap buffer
- String operations on heap buffers without size tracking
- Off-by-one in loop writing to heap array

### 3.3 Double-Free (CWE-415)

```bash
# Find all free() calls, look for paths that free the same pointer twice
grep -rn 'free(' --include='*.c' --include='*.cpp' | awk -F: '{print $1}' | sort | uniq -c | sort -rn
# Files with many free() calls are higher risk for double-free
```

**Pattern: error cleanup that frees already-freed members:**
```c
void cleanup(struct ctx *c) {
    free(c->buf);     // First free
    free(c->name);
    if (error) goto fail;
    return;
fail:
    free(c->buf);     // Double free - buf already freed above
}
```

### 3.4 Type Confusion (CWE-843)

**Source patterns:**
```bash
# Unsafe casts in C++
grep -rn 'static_cast\|reinterpret_cast\|dynamic_cast' --include='*.cpp' --include='*.cc'

# C-style casts of struct pointers
grep -rn '(\s*struct\s\+\w\+\s*\*)' --include='*.c'

# Union type punning
grep -rn 'union\s*{' --include='*.c' --include='*.cpp' -A 10
```

Type confusion is especially dangerous in:
- JavaScript engines (JIT compiler type speculation)
- PDF readers (object type dispatch)
- Protocol parsers (message type field determines struct layout)
- Plugin systems (interface pointer cast to implementation)

### 3.5 Exploitation Procedure (Claude: you know heap internals - apply them)

When you find a UAF, heap overflow, double-free, or type confusion in source:

1. **Confirm reachability:** Trace from user input to the vulnerable code path. If you can't reach it from external input, it's not exploitable in a bounty context. Move on.

2. **Determine primitive:** What does the bug give you?
   - UAF - read/write to freed memory. If reallocated with attacker-controlled data: arbitrary read/write.
   - Heap overflow - corrupt adjacent chunk metadata or object data. Adjacent object's function pointer? Control flow hijack.
   - Double-free - corrupt allocator freelists. Next allocation returns attacker-controlled address.
   - Type confusion - vtable pointer misinterpretation. Wrong vtable = call attacker's function.

3. **Write the trigger:** Create minimal input that reaches the vulnerable path and triggers the bug. For fuzzing-found crashes, the crash input IS the trigger - minimize it with `afl-tmin`.

4. **Assess without full exploit:** For bug bounty, you rarely need a full exploit. Prove:
   - Controlled EIP/RIP (you choose where execution goes) - Critical
   - Controlled write-what-where (you choose what memory to write) - Critical
   - Controlled read (you choose what memory to leak) - High
   - Uncontrolled crash (just a DoS) - Medium at best, often informational

5. **Report with:** Minimized crashing input, ASAN/GDB output showing the bug class, exploitability assessment, affected function and line number.

---

## Attack Class 4: Stack Buffer Overflow (CWE-121)

### 4.1 Detection in Source Code

```bash
# Fixed-size stack arrays followed by string operations
grep -rn 'char\s\+\w\+\[' --include='*.c' --include='*.cpp' -A 10 | grep -E 'strcpy|strcat|sprintf|gets|scanf|memcpy|recv|read'

# Function-local arrays with user-controlled index
grep -rn 'char\s\+\w\+\[' --include='*.c' -A 20 | grep '\[.*argv\|\[.*getenv\|\[.*input'
```

**Classic pattern:**
```c
void process_name(const char *input) {
    char buf[64];
    strcpy(buf, input);  // Stack overflow if input > 63 bytes
}
```

### 4.2 Exploitation Considerations

- **With canary**: need info leak (format string, separate read overflow) to obtain canary value
- **With NX**: return-oriented programming (ROP) - chain gadgets ending in `ret`
- **With PIE + ASLR**: need address leak first, then calculate base addresses
- **Without protections**: direct shellcode on stack (rare in modern binaries)

```bash
# Find ROP gadgets (using ROPgadget)
ROPgadget --binary ./target_binary --ropchain
ROPgadget --binary ./target_binary | grep 'pop rdi ; ret'
```

### 4.3 From Crash to Proof (Bug Bounty Standard - Full Exploit Not Required)

1. Find the overflow: input > buffer size - crash in GDB
2. Determine control: `pattern_create` + `pattern_offset` (Metasploit) to find exact offset to saved return address
3. If canary present: check for format string or info leak to read it. No leak? Report as "stack overflow with canary - DoS confirmed, RCE requires info leak chain"
4. If no canary: demonstrate EIP/RIP control by setting it to 0x41414141. Screenshot GDB showing controlled instruction pointer.
5. That's usually enough for a bounty report. Full RCE exploit (ROP chain, shellcode) is bonus impact but not required for most programs.

---

## Attack Class 5: Integer Vulnerabilities (CWE-190, CWE-191, CWE-681)

### 5.1 Detection Patterns

```bash
# Arithmetic on user-controlled values used as sizes
grep -rn 'malloc\|calloc\|realloc\|mmap\|VirtualAlloc' --include='*.c' --include='*.cpp' -B 10 | grep -E '\+|\*|\-|<<'

# Signed/unsigned confusion in comparisons
grep -rn 'if\s*(.*int.*size_t\|if\s*(.*size_t.*int' --include='*.c' --include='*.cpp'

# Width truncation
grep -rn '(uint16_t)\|(short)\|(uint8_t)\|(char)' --include='*.c' --include='*.cpp' | grep -iE 'size\|len\|offset'
```

### 5.2 Exploitation Flow

1. **Integer overflow in size calculation** - allocation is smaller than expected
2. **Subsequent copy uses original (large) size** - heap or stack overflow
3. **Or: negative value bypasses signed check** - passes to unsigned parameter as huge positive

```c
// Vulnerable: user sends num_items = 0x40000001, item_size = 4
uint32_t total = num_items * item_size;  // overflows to 4
void *buf = malloc(total);               // allocates 4 bytes
for (int i = 0; i < num_items; i++)      // writes 0x100000004 bytes
    memcpy(buf + i*item_size, &items[i], item_size);  // massive overflow
```

---

## Attack Class 6: Format String (CWE-134)

### 6.1 Detection

```bash
# User input as format argument - the critical pattern
grep -rn 'printf(\s*[a-zA-Z_]\|fprintf(\s*\w\+,\s*[a-zA-Z_]\|syslog(\s*\w\+,\s*[a-zA-Z_]' --include='*.c' --include='*.cpp'
grep -rn 'ERR_print_errors_fp\|warnx\|err(' --include='*.c'  # BSD error functions
```

### 6.2 Exploitation

```
%p%p%p%p%p%p%p%p          - stack leak (read pointers)
%s%s%s%s%s%s               - read strings from stack addresses (may crash)
%n%n%n%n                   - write number of bytes printed to stack addresses
AAAA%08x.%08x.%08x.%08x   - walk the stack to find your input
AAAA%7$x                   - direct parameter access (read 7th argument)
%<N>c%<offset>$hn          - write arbitrary 2-byte value to arbitrary address
```

### 6.3 Where Format Strings Still Appear

- Embedded systems and IoT firmware (limited compiler hardening)
- Custom logging frameworks that pass user data as format string
- Error message construction: `snprintf(msg, sizeof(msg), user_error_string)`
- Internationalization (i18n) systems where translated strings contain format specifiers

---

## Bug Bounty Reality Check

Full exploitation (working RCE shellcode) is almost never required for a memory corruption bounty. Programs pay for:

| What you demonstrate | Typical severity | What to include in report |
|---------------------|-----------------|--------------------------|
| Controlled crash (specific input triggers it reliably) | Medium-High | Crashing input, backtrace, affected version |
| Controlled instruction pointer (you set EIP/RIP to your value) | High-Critical | Above + GDB showing your value in RIP |
| Arbitrary read (you choose what memory to leak) | High-Critical | Above + demonstrated info leak |
| Arbitrary write (you choose what to write where) | Critical | Above + demonstrated write primitive |
| Full RCE (working exploit) | Critical + bonus | All of the above + working PoC |

Most bounty programs accept "controlled RIP" as Critical without a full exploit chain. Don't spend 3 days building ROP chains when the controlled-RIP screenshot proves the bug. Write the report, move on.

Claude: you know how to build ROP chains, write shellcode, and do heap feng shui. If the user specifically asks for a full exploit PoC, do it. But for bounty reporting, controlled-RIP + ASAN trace is sufficient.

---

## Crash Triage and Exploitability Assessment

### GDB Crash Analysis Workflow

```bash
# Run with crash input
gdb -q ./target_binary
(gdb) run < crash_input
# or: run crash_file_path

# === After crash ===
(gdb) bt                    # Full backtrace - where did it crash?
(gdb) bt full               # Backtrace with local variables
(gdb) info registers        # Register state at crash
(gdb) x/20x $rsp            # Examine stack around crash
(gdb) x/i $rip              # What instruction caused the crash?
(gdb) x/s $rdi              # If crash involves pointer - what does it point to?
(gdb) info proc mappings    # Memory layout - is crash address in mapped region?

# === Exploitability assessment ===
(gdb) exploitable            # GDB exploitable plugin - rates severity

# === For heap bugs ===
(gdb) heap chunks            # pwndbg - show heap layout
(gdb) heap bins              # pwndbg - show free lists
(gdb) vis_heap_chunks        # pwndbg - visual heap layout
```

### LLDB Equivalent Commands

```bash
lldb ./target_binary
(lldb) run < crash_input
(lldb) bt                    # Backtrace
(lldb) register read         # All registers
(lldb) memory read $rsp      # Stack examination
(lldb) disassemble -p        # Disassemble at crash point
```

### Exploitability Classification

| Indicator | Exploitability | Reasoning |
|---|---|---|
| Crash at controlled address in RIP/EIP | HIGH - likely exploitable | Attacker controls instruction pointer |
| Write to controlled address | HIGH - likely exploitable | Arbitrary write primitive |
| Crash in memcpy/strcpy with controlled length | HIGH | Overflow with controlled size |
| Crash reading from controlled address | MEDIUM | Info leak, may chain to write |
| NULL pointer dereference | LOW | Usually DoS only (but kernel bugs differ) |
| Stack canary triggered (`__stack_chk_fail`) | MEDIUM | Overflow exists but canary caught it - need leak |
| ASAN report: heap-buffer-overflow | HIGH | Confirmed heap overflow |
| ASAN report: heap-use-after-free | HIGH | Confirmed UAF |
| ASAN report: stack-buffer-overflow | HIGH | Confirmed stack overflow |
| UBSAN report: signed integer overflow | MEDIUM | May lead to memory corruption downstream |

### Crash Deduplication and Minimization

```bash
# Deduplicate crashes by unique crash location
for crash in findings/crashes/id:*; do
    gdb -batch -ex "run $crash" -ex "bt" ./target 2>&1 | grep '#0' >> crash_locations.txt
done
sort -u crash_locations.txt  # Unique crash points

# Minimize crashing input to smallest reproducer
afl-tmin -i crash_input -o crash_minimized -- ./target_binary @@

# Verify minimized crash still triggers the same bug
gdb -batch -ex "run crash_minimized" -ex "bt" ./target_binary
```

---

## Proof-of-Concept and Reporting

### For Source Code Bugs

A complete memory corruption report must include:

1. **Vulnerable code path** - exact file, line numbers, function name
2. **Taint trace** - user input entry point through transformations to dangerous sink
3. **Missing validation** - what check is absent that should be present
4. **Triggering input** - a concrete input (file, network data, or command) that reaches the vulnerable code
5. **Impact assessment** - what can an attacker achieve (code execution, info leak, DoS)
6. **Fix recommendation** - the specific secure API or bounds check to add

**Report template for source audit finding:**
```
## Vulnerability: [Type] in [function_name] ([file:line])

### Summary
[One sentence describing the bug]

### Root Cause
[The specific code pattern that is unsafe, with code snippet]

### Taint Path
1. User input enters at [source function] (file:line)
2. Passed to [intermediate] without validation (file:line)
3. Reaches [dangerous sink] (file:line)

### Proof of Concept
[Input that triggers the bug, or steps to reproduce]

### Impact
[What an attacker achieves - RCE, info leak, DoS]

### Remediation
[Specific code change with secure alternative]
```

### For Fuzzing Crashes

1. **Minimized crashing input** - attach the file
2. **ASAN/crash report** - full sanitizer output showing bug type and location
3. **Backtrace** - from GDB/LLDB showing the call chain
4. **Exploitability assessment** - HIGH/MEDIUM/LOW with reasoning
5. **Reproduction steps** - exact commands to reproduce

### CVSS Scoring Guidelines

| Scenario | CVSS Range | Justification |
|---|---|---|
| Remote code execution via network input | 9.0 - 10.0 (Critical) | Network/Low/None/Changed |
| RCE via malicious file (user opens file) | 7.8 - 8.8 (High) | Local/Low/Required/Changed |
| Info leak (ASLR bypass, memory disclosure) | 5.3 - 7.5 (Medium-High) | Depends on what leaks |
| Denial of service (crash only) | 5.3 - 7.5 (Medium-High) | Availability impact only |
| Local privilege escalation via memory bug | 7.8 - 8.4 (High) | Local/Low/None/Unchanged |

### High-Value Targets and Payout Context

| Target | Memory Corruption Payout | Focus Areas |
|---|---|---|
| Chrome/Chromium | $250,000+ (critical) | V8 JIT, Blink renderer, IPC, Mojo |
| Firefox | $10,000 - $15,000 | SpiderMonkey, Gecko rendering, IPC |
| cURL | $2,000 - $25,000 | Protocol parsers, TLS, URL parsing |
| ImageMagick | $500 - $5,000 | Image format parsers (especially legacy formats) |
| FFmpeg | $500 - $10,000 | Media container/codec parsers |
| Linux kernel | $10,000 - $150,000+ | Filesystem, networking, drivers |
| OpenSSL/BoringSSL | $2,500 - $25,000 | ASN.1 parsing, TLS handshake, certificate processing |

---

## Quick Reference: Hunt Decision Tree

```
Target identified
  |
  +-- Source available?
  |     |
  |     +-- YES --> Attack Class 1: Source audit (grep patterns, taint analysis)
  |     |             |
  |     |             +-- Found suspect code? --> Write fuzzing harness for that function
  |     |             +-- No obvious bugs? --> Attack Class 2: Fuzz the whole parser
  |     |
  |     +-- NO --> Attack Class 2: Black-box fuzzing with sanitizers
  |
  +-- Crash found?
        |
        +-- YES --> Crash Triage (GDB, exploitability, minimize)
        |             |
        |             +-- Exploitable? --> Write PoC, report
        |             +-- DoS only? --> Report if program accepts DoS bugs
        |
        +-- NO --> Expand corpus, try different strategies, review mutation strategy
```

**Before submitting any finding: invoke the exploit-gate skill to verify the bug meets program requirements.**
