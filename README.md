# RNG_DETECTOR

## Static Analysis and Detection of Cryptographic / RNG APIs in Windows PE Binaries

`RNG_DETECTOR` is a Windows-oriented static binary-analysis project for
examining compiled PE executables and identifying the use of
cryptographic and random-number-generation APIs.

The project currently focuses on Windows x86-64 PE binaries and Windows
CNG (`bcrypt.dll`). The long-term goal is to move from simple API
detection to explainable argument recovery and data-flow analysis.

------------------------------------------------------------------------

## 1. Project Goal

The project is intended to answer increasingly detailed questions about
a compiled executable:

1.  **Does the binary use a cryptographic RNG?**
2.  **Which cryptographic APIs does it import?**
3.  **Where are those APIs actually called?**
4.  **Which import thunk and IAT entry does each call resolve through?**
5.  **What values are passed to the API?**
6.  **Where did those values come from?**
7.  **Which buffers, lengths, keys, IVs, and flags participate in the
    cryptographic operation?**
8.  **How does data flow between cryptographic API calls?**

The development therefore progresses from:

``` text
API Import Detection
        ↓
API Call-Site Detection
        ↓
Register / Argument Recovery
        ↓
Data-Flow Analysis
        ↓
Cryptographic Behavior Analysis
```

------------------------------------------------------------------------

# 2. Why This Project Exists

Finding an API name in a binary is useful, but it is not enough.

For example, discovering:

``` text
BCryptGenRandom
```

in the PE import table tells us that the executable depends on the
function.

It does **not** automatically tell us:

-   whether the function is actually called,
-   where it is called,
-   what buffer receives the random bytes,
-   how many bytes are requested,
-   what flags are supplied,
-   where the output is subsequently used.

Similarly, finding:

``` text
BCryptEncrypt
```

does not tell us:

-   which key is used,
-   which plaintext buffer is encrypted,
-   which IV is supplied,
-   how large the input is,
-   where the ciphertext goes.

The project therefore tries to connect the PE import information with
actual machine-code execution points.

------------------------------------------------------------------------

# 3. Static Analysis Model

The basic model is:

``` text
                   Windows PE executable
                            |
              +-------------+-------------+
              |                           |
              v                           v
        PE Import Table              Machine Code
              |                           |
              v                           v
        Imported APIs                 CALL instructions
              |                           |
              +-------------+-------------+
                            |
                            v
                    API Call-Site Mapping
                            |
                            v
                    Argument Recovery
                            |
                            v
                      Data Flow
```

This is static analysis: the executable is inspected without needing to
execute its cryptographic code.

------------------------------------------------------------------------

# 4. Current Environment

The project has been developed using:

-   Windows
-   PowerShell
-   Visual Studio Code
-   Python
-   LLVM
-   `llvm-objdump`
-   `clang-cl`

Typical tools:

``` text
clang-cl
llvm-objdump
python
```

------------------------------------------------------------------------

# 5. Test Program

A major test program is:

``` text
good_real_aes_cbc.c
```

It is compiled as:

``` powershell
clang-cl /Od good_real_aes_cbc.c /Fe:good_real_Od.exe
```

The `/Od` option disables optimization.

This is intentionally useful during early reverse-engineering
development because the assembly tends to retain a clearer relationship
with the source code.

The resulting test binary is:

``` text
good_real_Od.exe
```

It was successfully run and produced output in the form:

``` text
AES-CBC encryption completed
IV: ...
Ciphertext: ...
```

Generated binaries such as `.exe` files should normally **not** be
committed to Git.

------------------------------------------------------------------------

# 6. Why `/Od` Is Being Used

Compiler optimization can make binary analysis substantially harder.

With optimization enabled, the compiler may:

-   remove variables,
-   reuse registers,
-   reorder instructions,
-   inline functions,
-   eliminate loads/stores,
-   keep values in registers,
-   combine operations.

Therefore development starts with:

``` text
/Od
```

and should eventually expand to:

``` text
/O1
/O2
/Ox
```

and ideally different compilers as well.

A robust analyzer must not depend on unoptimized assembly.

------------------------------------------------------------------------

# 7. AES and RNG Are Different Things

An important conceptual distinction in this project is:

``` text
Random-number generation
```

versus:

``` text
AES encryption
```

If an application uses Windows CNG, the executable may not contain an
obvious implementation of AES rounds such as:

``` text
SubBytes
ShiftRows
MixColumns
AddRoundKey
```

Instead, the application may simply call:

``` text
BCryptEncrypt(...)
```

and the Windows cryptographic provider performs the AES implementation
internally.

Similarly, random bytes can be obtained through:

``` text
BCryptGenRandom(...)
```

Therefore this project initially operates at the **API boundary**,
rather than attempting to identify AES round operations inside
`bcrypt.dll`.

------------------------------------------------------------------------

# 8. Windows CNG APIs Found in the Test Binary

The test executable imports the following important functions from:

``` text
bcrypt.dll
```

``` text
BCryptCloseAlgorithmProvider
BCryptDestroyKey
BCryptEncrypt
BCryptGenRandom
BCryptGenerateSymmetricKey
BCryptGetProperty
BCryptOpenAlgorithmProvider
BCryptSetProperty
```

The important classifications currently used are:

``` text
BCryptGenRandom
    -> OS cryptographic RNG

BCryptEncrypt
    -> Windows CNG encryption API

BCryptGenerateSymmetricKey
    -> Windows CNG symmetric-key API

BCryptOpenAlgorithmProvider
    -> Windows CNG algorithm API

BCryptSetProperty
    -> Windows CNG property API

BCryptGetProperty
    -> Windows CNG property API
```

Other imported functions come from normal Windows system libraries and
are not automatically considered cryptographic.

------------------------------------------------------------------------

# 9. Windows x64 Calling Convention

Argument analysis depends heavily on the Windows x64 calling convention.

For normal integer and pointer arguments, the first four arguments are
passed in:

``` text
RCX
RDX
R8
R9
```

Conceptually:

``` c
function(a, b, c, d, e);
```

corresponds approximately to:

``` text
RCX = a
RDX = b
R8  = c
R9  = d
stack = e
```

This is essential for APIs such as:

``` text
BCryptGenRandom
BCryptEncrypt
BCryptGenerateSymmetricKey
```

because the argument analyzer must determine what values exist in these
locations immediately before the call.

------------------------------------------------------------------------

# 10. PE Import Table

The PE import table describes external functions required by the
executable.

For the test binary, the relevant section includes:

``` text
DLL Name: bcrypt.dll

BCryptCloseAlgorithmProvider
BCryptDestroyKey
BCryptEncrypt
BCryptGenRandom
BCryptGenerateSymmetricKey
BCryptGetProperty
BCryptOpenAlgorithmProvider
BCryptSetProperty
```

The import parser reconstructs a mapping conceptually equivalent to:

``` text
IAT address -> DLL -> API
```

For example:

``` text
0x140020c60 -> bcrypt.dll -> BCryptEncrypt
0x140020c68 -> bcrypt.dll -> BCryptGenRandom
```

------------------------------------------------------------------------

# 11. Import Address Table (IAT)

The Import Address Table is one of the key PE structures used by this
project.

Conceptually:

``` text
Executable
    |
    v
   IAT
    |
    +--> BCryptGenRandom
    |
    +--> BCryptEncrypt
    |
    +--> ...
```

The actual runtime addresses of imported functions are resolved by
Windows.

The analyzer therefore uses the IAT as one layer of the call-resolution
process.

------------------------------------------------------------------------

# 12. Import Thunks

A call site frequently does not directly call the IAT entry.

Instead, a linker-generated import thunk can look like:

``` asm
1400177a0:
    ff 25 c2 94 00 00
    jmpq *0x94c2(%rip)
```

which resolves to:

``` text
0x140020c68
```

The resulting chain is:

``` text
CALL SITE
    |
    v
IMPORT THUNK
    |
    v
IAT ENTRY
    |
    v
DLL + API
```

For example:

``` text
0x14000101e
    |
    v
0x1400177a0
    |
    v
0x140020c68
    |
    v
bcrypt.dll
    |
    v
BCryptGenRandom
```

This multi-level resolution is a central part of the project.

------------------------------------------------------------------------

# 13. Example: BCryptGenRandom

One successful result from the test binary is:

``` text
CALL SITE : 0x14000101e
TARGET    : 0x1400177a0
IAT       : 0x140020c68
DLL       : bcrypt.dll
API       : BCryptGenRandom
```

The surrounding instructions include:

``` asm
140001012: 41 b8 10 00 00 00
140001018: 41 b9 02 00 00 00
14000101e: e8 7d 67 01 00
```

which disassemble to:

``` asm
movl $0x10, %r8d
movl $0x2, %r9d
callq 0x1400177a0
```

This demonstrates why register analysis is the next important step.

The analyzer should eventually explain the argument state at the call
instead of merely reporting the API.

------------------------------------------------------------------------

# 14. Example: BCryptEncrypt

Another successful call-site result is:

``` text
CALL SITE : 0x140001245
TARGET    : 0x140017790
IAT       : 0x140020c60
DLL       : bcrypt.dll
API       : BCryptEncrypt
```

The instructions immediately before the call prepare registers and stack
arguments.

The important future question is:

``` text
What exactly is in RCX?
What exactly is in RDX?
What exactly is in R8?
What exactly is in R9?
What stack arguments are present?
```

and then:

``` text
Where did those values originate?
```

------------------------------------------------------------------------

# 15. Analyzer 1: Import Analyzer

File:

``` text
binary_import_analyzer.py
```

Purpose:

-   Parse PE imports.
-   List imported APIs.
-   Identify RNG APIs.
-   Identify cryptographic APIs.
-   Classify APIs.

Example:

``` text
Detected RNG APIs
-----------------

RNG API          : BCryptGenRandom
Classification   : OS cryptographic RNG
```

and:

``` text
Detected Cryptographic APIs
---------------------------

Crypto API       : BCryptEncrypt
Classification   : Windows CNG encryption API

Crypto API       : BCryptGenerateSymmetricKey
Classification   : Windows CNG symmetric-key API

Crypto API       : BCryptOpenAlgorithmProvider
Classification   : Windows CNG algorithm API
```

This stage answers:

> What cryptographic/RNG APIs does this binary import?

------------------------------------------------------------------------

# 16. Analyzer 2: Call-Site Analyzer

File:

``` text
binary_call_analyzer.py
```

Purpose:

Find actual call instructions and resolve:

``` text
CALL
  |
  v
Import Thunk
  |
  v
IAT
  |
  v
DLL + API
```

For the test binary it successfully identified:

``` text
0x14000101e -> BCryptGenRandom
0x1400010c6 -> BCryptOpenAlgorithmProvider
0x14000110c -> BCryptSetProperty
0x140001156 -> BCryptGetProperty
0x1400011b7 -> BCryptGenerateSymmetricKey
0x140001245 -> BCryptEncrypt
```

It also resolves cleanup calls such as:

``` text
BCryptDestroyKey
BCryptCloseAlgorithmProvider
```

This stage answers:

> Where in the binary are the cryptographic APIs actually called?

------------------------------------------------------------------------

# 17. Analyzer 3: Argument Analyzer

File:

``` text
binary_argument_analyzer.py
```

This is the current development focus.

The goal is to move from:

``` text
BCryptGenRandom was called at 0x14000101e
```

to:

``` text
BCryptGenRandom was called at 0x14000101e

RCX = ?
RDX = ?
R8  = 0x10
R9  = 0x2
```

and eventually:

``` text
RCX = pointer to output buffer
RDX = length / parameter
R8  = ...
R9  = flags
```

with an explanation of where each value came from.

------------------------------------------------------------------------

# 18. Why Argument Analysis Is Hard

Consider:

``` asm
movq %rax, %rcx
movl $0x10, %r8d
xor  %r9d, %r9d
callq ...
```

We can immediately infer:

``` text
R8 = 0x10
R9 = 0
```

But:

``` text
RCX = RAX
```

does not tell us what `RAX` contains.

We have to look backward:

``` text
Earlier instruction
      |
      v
RAX gets a value
      |
      v
mov RAX -> RCX
      |
      v
API call
```

This makes argument recovery a **data-flow analysis problem**.

------------------------------------------------------------------------

# 19. First Data-Flow Strategy

The initial strategy is a bounded backward scan.

For every target API call:

``` text
CALL BCryptEncrypt
```

look backward through a limited number of instructions and track:

``` text
RCX
RDX
R8
R9
```

The first implementation should handle simple cases before attempting
sophisticated symbolic execution.

The development sequence should be:

``` text
Immediate constants
       ↓
Register copies
       ↓
Zeroing instructions
       ↓
Stack loads
       ↓
LEA/address calculations
       ↓
Longer register chains
       ↓
Basic-block aware analysis
```

------------------------------------------------------------------------

# 20. Register State

A useful conceptual representation is:

``` python
registers = {
    "rcx": ...,
    "rdx": ...,
    "r8": ...,
    "r9": ...
}
```

For:

``` asm
movq %rax, %rcx
```

we know:

``` text
RCX <- RAX
```

Therefore the analyzer can follow:

``` text
RCX
 |
 v
RAX
```

and continue looking backward.

------------------------------------------------------------------------

# 21. Immediate Values

For:

``` asm
movl $0x10, %r8d
```

the analyzer can report:

``` text
R8 = constant 0x10
```

This is one of the easiest and most reliable forms of argument recovery.

------------------------------------------------------------------------

# 22. Zeroing Idioms

The analyzer should recognize instructions such as:

``` asm
xorl %r9d, %r9d
```

as:

``` text
R9 = 0
```

Likewise:

``` asm
xorq %rax, %rax
```

means:

``` text
RAX = 0
```

Recognizing common compiler idioms is important because compilers
frequently use XOR to zero registers.

------------------------------------------------------------------------

# 23. Memory Arguments

An instruction such as:

``` asm
movq 0x30(%rsp), %rdx
```

means:

``` text
RDX = memory[RSP + 0x30]
```

This is different from:

``` asm
leaq 0x30(%rsp), %rdx
```

which means:

``` text
RDX = address(RSP + 0x30)
```

The analyzer must preserve the distinction between:

``` text
value
```

and:

``` text
address of value
```

because cryptographic APIs frequently receive pointers to buffers.

------------------------------------------------------------------------

# 24. Pointer Tracking

Eventually, values should be represented with types such as:

``` text
constant
register
memory value
memory address
unknown
```

For example:

``` text
R8  = constant(0x10)

R9  = constant(0)

RCX = register(RAX)

RDX = memory([RSP + 0x30])
```

A later stage can resolve:

``` text
RAX -> stack buffer
```

or:

``` text
RAX -> heap allocation
```

if sufficient information is available.

------------------------------------------------------------------------

# 25. Call-Site Data-Flow Goal

The ideal output eventually looks something like:

``` text
============================================================
BCryptEncrypt
============================================================

Call site:
    0x140001245

Arguments:

RCX:
    value = 0x...
    type  = pointer
    source:
        0x140001217
        lea 0x84(%rsp), %rax
        ...
        mov %rax, %rcx

RDX:
    value = ...
    source:
        ...

R8:
    value = 0x10
    source:
        0x140001226
        mov $0x10, ...

R9:
    value = 0
    source:
        ...
```

The exact output format can evolve.

The important goal is **explainability**.

------------------------------------------------------------------------

# 26. Explainability Is a Core Design Goal

The tool should eventually explain:

``` text
WHAT
```

was detected,

``` text
WHERE
```

it was detected,

``` text
HOW
```

it was resolved,

and:

``` text
WHY
```

the analyzer believes a particular argument has a particular value.

For example:

``` text
BCryptGenRandom
Call site: 0x14000101e

R8 = 0x10

Reason:
    instruction 0x140001012 writes 0x10 to R8D
```

This is much more useful than simply printing:

``` text
R8 = 16
```

------------------------------------------------------------------------

# 27. Current Successful Call Resolution

The current working call analyzer can reconstruct:

``` text
CALL 0x14000101e
    ->
THUNK 0x1400177a0
    ->
IAT 0x140020c68
    ->
bcrypt.dll / BCryptGenRandom
```

and:

``` text
CALL 0x140001245
    ->
THUNK 0x140017790
    ->
IAT 0x140020c60
    ->
bcrypt.dll / BCryptEncrypt
```

This is the foundation for argument recovery.

------------------------------------------------------------------------

# 28. Important Limitations

## 28.1 Direct calls

The current approach is strongest for direct calls such as:

``` asm
callq 0x1400177a0
```

Indirect calls such as:

``` asm
call *%rax
```

require additional analysis.

------------------------------------------------------------------------

## 28.2 Optimized binaries

Register reuse and instruction reordering make `/O1` and `/O2`
substantially harder.

------------------------------------------------------------------------

## 28.3 Branches

A simple backward scan can become incorrect when control flow contains:

``` text
if (...)
    RCX = A;
else
    RCX = B;

CALL(...)
```

A future CFG-based analyzer is needed to handle this correctly.

------------------------------------------------------------------------

## 28.4 Aliasing

Two pointers can refer to the same underlying memory.

Static analysis may not always be able to prove that relationship.

------------------------------------------------------------------------

# 29. Future Architecture

The planned progression is:

``` text
                 PE executable
                       |
                       v
                Import parser
                       |
                       v
                 API detector
                       |
                       v
               Thunk resolver
                       |
                       v
              Call-site detector
                       |
                       v
             Register analyzer
                       |
                       v
              Stack analyzer
                       |
                       v
             Pointer tracking
                       |
                       v
               Basic blocks
                       |
                       v
                     CFG
                       |
                       v
           Branch-aware data flow
                       |
                       v
             Inter-call analysis
                       |
                       v
       Cryptographic behavior report
```

The project should not jump directly to full symbolic execution.

Each layer should be tested first.

------------------------------------------------------------------------

# 30. Testing Strategy

The project should maintain deliberately simple test binaries.

### Test 1: RNG only

``` c
BCryptGenRandom(...);
```

Expected:

``` text
BCryptGenRandom detected
```

### Test 2: Encryption only

``` c
BCryptEncrypt(...);
```

Expected:

``` text
BCryptEncrypt detected
```

### Test 3: RNG + AES

``` text
BCryptGenRandom
      |
      v
key/IV/buffer
      |
      v
BCryptEncrypt
```

Expected:

``` text
Both APIs detected
```

### Test 4: No cryptography

A binary without cryptographic APIs.

Expected:

``` text
No RNG API
No cryptographic API
```

### Test 5: Optimization

Compile the same program with:

``` powershell
clang-cl /O1 ...
```

and verify that API/call-site detection remains functional.

### Test 6: Multiple calls

Call the same API multiple times and ensure every call site is reported.

------------------------------------------------------------------------

# 31. Useful Commands

Compile:

``` powershell
clang-cl /Od good_real_aes_cbc.c /Fe:good_real_Od.exe
```

Run:

``` powershell
.\good_real_Od.exe
```

Inspect PE imports:

``` powershell
llvm-objdump -p good_real_Od.exe
```

Save import output:

``` powershell
llvm-objdump -p good_real_Od.exe > real_imports.txt
```

Disassemble:

``` powershell
llvm-objdump -d good_real_Od.exe > real_Od_disasm.txt
```

Focused disassembly:

``` powershell
llvm-objdump -d good_real_Od.exe --start-address=0x140001000 --stop-address=0x140001300
```

Run import analyzer:

``` powershell
python binary_import_analyzer.py good_real_Od.exe
```

Run call analyzer:

``` powershell
python binary_call_analyzer.py good_real_Od.exe
```

Run argument analyzer:

``` powershell
python binary_argument_analyzer.py good_real_Od.exe
```

------------------------------------------------------------------------

# 32. Recommended Repository Structure

A clean future repository could look like:

``` text
RNG_DETECTOR/
│
├── README.md
├── .gitignore
│
├── binary_import_analyzer.py
├── binary_call_analyzer.py
├── binary_argument_analyzer.py
│
├── good_real_aes_cbc.c
│
├── tests/
│   ├── test_imports.py
│   ├── test_call_sites.py
│   └── test_arguments.py
│
└── docs/
    ├── architecture.md
    ├── windows_x64_calling_convention.md
    └── analysis_notes.md
```

Generated binaries and large disassembly dumps should normally remain
outside the Git repository.

------------------------------------------------------------------------

# 33. Git Workflow

Git is used to create safe checkpoints.

The basic workflow is:

``` powershell
git status
git diff
git add .
git commit -m "Describe the change"
git push
```

Important commands:

  Command                 Meaning
  ----------------------- ------------------------------
  `git status`            Show changed/untracked files
  `git diff`              Show code changes
  `git add .`             Stage changes
  `git commit -m "..."`   Create a checkpoint
  `git push`              Upload commits to GitHub
  `git pull`              Download remote changes

A good project habit is:

> Commit whenever the analyzer reaches a known-good state.

For example:

``` text
Commit 1
    Import detection working

Commit 2
    API call-site detection working

Commit 3
    Argument constants recovered

Commit 4
    Register propagation working

Commit 5
    Stack arguments recovered
```

This is particularly useful when experimenting with binary-analysis
logic.

------------------------------------------------------------------------

# 34. `.gitignore`

The repository should generally ignore generated artifacts:

``` gitignore
__pycache__/
*.pyc

*.exe
*.dll
*.obj
*.lib

*.txt

.venv/
venv/

.vscode/

*.tmp
*.log

Thumbs.db
.DS_Store
```

The reason for ignoring `*.txt` is that current files such as:

``` text
real_imports.txt
real_Od_disasm.txt
```

are generated analysis output rather than source code.

If an important documentation file eventually uses `.txt`, the rule can
be changed.

------------------------------------------------------------------------

# 35. Development Rules

When extending the project:

1.  Do not break import parsing.
2.  Do not break call-site resolution.
3.  Add one capability at a time.
4.  Test against `good_real_Od.exe`.
5.  Keep useful debug output while developing.
6.  Make verbose debugging optional once the logic stabilizes.
7.  Prefer small functions over one huge function.
8.  Keep generic instruction parsing separate from API-specific
    semantics.
9.  Do not assume every compiler emits the same assembly.
10. Test both `/Od` and optimized binaries.
11. Use Git commits as checkpoints.
12. Document important discoveries.
13. Prefer explainable results over unexplained guesses.
14. Clearly distinguish `known`, `inferred`, and `unknown` values.

------------------------------------------------------------------------

# 36. Important Terminology

### PE

Portable Executable, the Windows executable file format.

### DLL

Dynamic-link library.

Example:

``` text
bcrypt.dll
```

### API

A function exported by a DLL.

Example:

``` text
BCryptGenRandom
```

### Import

An external function required by an executable.

### IAT

Import Address Table.

A PE structure used for imported function addresses.

### Import thunk

A small piece of code that transfers execution through an IAT entry.

### Call site

The address of a `call` instruction.

Example:

``` text
0x14000101e
```

### Register argument

A function argument stored in a calling-convention register such as:

``` text
RCX
RDX
R8
R9
```

### Data flow

The chain describing where a value originates and how it moves through
instructions.

### Static analysis

Analyzing the executable without executing the target program.

------------------------------------------------------------------------

# 37. Mental Model for the Whole Project

The most useful mental model is:

``` text
SOURCE CODE
    |
    | clang-cl
    v
PE EXECUTABLE
    |
    +--------------------------+
    |                          |
    v                          v
IMPORT TABLE              MACHINE CODE
    |                          |
    v                          v
IAT                       CALL SITE
    |                          |
    +------------+-------------+
                 |
                 v
           IMPORT THUNK
                 |
                 v
             TARGET API
                 |
                 v
            ARGUMENTS
                 |
                 v
             REGISTERS
                 |
                 v
            STACK / MEMORY
                 |
                 v
             DATA FLOW
                 |
                 v
       CRYPTOGRAPHIC BEHAVIOR
```

The project is gradually moving down this chain.

------------------------------------------------------------------------

# 38. Current Milestone

The current milestone is:

> Given a Windows PE executable, identify cryptographic/RNG API call
> sites and recover the arguments passed to those APIs.

For example, the eventual output should look conceptually like:

``` text
BCryptGenRandom
    Call site : 0x14000101e
    RCX       : ...
    RDX       : ...
    R8        : 0x10
    R9        : 0x2

BCryptEncrypt
    Call site : 0x140001245
    RCX       : ...
    RDX       : ...
    R8        : ...
    R9        : ...
```

The `...` values should be replaced only when the analyzer can justify
them.

------------------------------------------------------------------------

# 39. Current Successful Achievement

The most important successful result so far is that the project can
resolve the complete chain:

``` text
CALL
0x14000101e
    |
    v
IMPORT THUNK
0x1400177a0
    |
    v
IAT
0x140020c68
    |
    v
bcrypt.dll
    |
    v
BCryptGenRandom
```

and:

``` text
CALL
0x140001245
    |
    v
IMPORT THUNK
0x140017790
    |
    v
IAT
0x140020c60
    |
    v
bcrypt.dll
    |
    v
BCryptEncrypt
```

This is the foundation for the argument/data-flow analyzer.

------------------------------------------------------------------------

# 40. Next Development Step

The immediate next task is to improve:

``` text
binary_argument_analyzer.py
```

so it can inspect instructions before a target call and recover:

``` text
RCX
RDX
R8
R9
```

with a source/explanation for each recovered value.

The expected progression is:

``` text
Immediate constants
        ↓
Register copies
        ↓
Zeroing instructions
        ↓
Stack loads
        ↓
LEA/address calculations
        ↓
Register chains
        ↓
Basic blocks
        ↓
CFG
        ↓
Branch-aware data flow
        ↓
Inter-call data flow
```

------------------------------------------------------------------------

# 41. Final Summary

`RNG_DETECTOR` is a static-analysis project for understanding
cryptographic and RNG usage in Windows PE binaries.

The project has three major analysis levels:

``` text
LEVEL 1
What cryptographic APIs are imported?

        ↓

LEVEL 2
Where are those APIs actually called?

        ↓

LEVEL 3
What arguments/data are passed to those calls?
```

Level 1 is working.

Level 2 is working for the current direct import-thunk pattern.

Level 3 is the current development focus.

The eventual goal is to transform raw binary instructions into an
understandable explanation:

``` text
Raw machine code
      ↓
API call
      ↓
Arguments
      ↓
Buffers / lengths / keys / IVs / flags
      ↓
Data flow
      ↓
Cryptographic behavior
```

This README should evolve with the project. Whenever a significant
architectural decision, discovery, limitation, or new analysis
capability is added, document it here or in the `docs/` directory.
