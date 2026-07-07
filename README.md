# Krypton (Continuation Fork)
`.NET Reactor` devirtualizer continuation focused on producing a **runnable devirtualized output**, not only a disassembly report.

## Credits
This repository is based on the original work by PeterG75:

- Upstream: [https://github.com/PeterG75/Krypton](https://github.com/PeterG75/Krypton)

Huge credit to the upstream project for the foundation. This fork extends the pipeline, runtime stability, and build workflow for modern `net8.0` usage.

## What This Repo Does
Krypton processes a virtualized assembly and reconstructs virtualized methods back into regular IL:

1. `ResourceParsing` - locates VM payload and decodes layout (operands, strings, method keys).
2. `OpcodeMapping` - finds the handler switch method and maps VM byte -> semantic opcode via pattern matching.
3. `MethodDisassembling` - disassembles VM methods into an intermediate model.
4. `SemanticValidation` - runs a lightweight VM semantic validator (CFG + stack effects) and adjusts unsafe low-confidence mappings.
5. `MethodRecompiling` - translates VM model back into compilable CIL.
6. `MethodReplacing` - replaces virtualized method bodies with recompiled ones.
7. `HiddenCallRecovery` - recovers NET Reactor "Hide Method Calls" stubs back into direct calls.
8. `PostDeobfuscation` - renames obfuscated members, inlines trivial wrappers, simplifies control flow, and neutralizes leftover runtime.
9. `StringDecryption` - inlines NET Reactor string-decoder call sites as literals (opt-in).
10. `ResourceDecryption` - restores AES+deflate protected embedded resources (opt-in).

## What Was Improved In This Fork
### 1) Project modernization
- Main projects migrated to `net8.0`.
- Dependency updates:
  - `AsmResolver.DotNet` -> `5.5.1`
  - `Colorful.Console` -> `1.2.15`
- Hardened build script (`build-all.ps1`) for robust execution from any directory and proper fail-fast behavior.

### 2) Safer IL recompilation (runtime correctness)
- Explicit exception handler reconstruction (`try/catch/finally/filter/fault`).
- Protected-region branch normalization:
  - `br` is upgraded to `leave` when jumping out of protected regions.
- `VMOpCode.Leave` is translated as `endfinally` for virtualized finally-handler semantics.
- Better local type inference and improved translation for `ldobj/stobj`, calls, arrays, and switch flows.

### 3) Runtime stabilization for devirtualized output
- Safer write pipeline with fallback strategy:
  - donor rewrite + controlled patching,
  - preservation of critical metadata indices,
  - invalid type-ref scope repair,
  - malformed custom-attribute cleanup when needed.
- Reactor/WinForms stabilization enabled by default:
  - `Hashtable::.ctor(int)` capacity sanitization,
  - WinForms entry guard bypass (pattern-based),
  - anti-manipulation method neutralization (string/API heuristics),
  - shared bootstrap worker neutralization (generic heuristic).

### 4) Better diagnostics and observability
- Detailed per-method report generation:
  - total/mapped/unknown instruction counts,
  - unknown VM bytes,
  - handler snippets for unmapped opcodes.
- Safety behavior for unknown opcodes:
  - methods with unresolved opcodes are skipped for recompilation,
  - output is written only if at least one method was recompiled successfully.

### 5) Hidden-call recovery and post-deobfuscation
- `HiddenCallRecovery`: runs the `Krypton.Runner` helper (`net48`) against the original
  assembly to capture the runtime `DynamicMethod` delegate table, builds a
  `field-token -> real callee` map, and rewrites the `ldsfld <delegate>; Invoke` stub
  pattern back into direct `call`/`callvirt` instructions.
- `PostDeobfuscation`: dynamic, pattern-based cleanup (no hardcoding) - renames
  obfuscated members, inlines trivial wrappers and resolved delegate calls, simplifies
  opaque/constant control flow, repairs malformed expressions (e.g. AES
  `TransformFinalBlock` length), and rebuilds WinForms constructor / `Dispose` / entry point.
- `StringDecryption` / `ResourceDecryption`: opt-in recovery of NET Reactor string and
  embedded-resource encryption (skips gracefully on RSA/NecroBit-tier blobs).

## Practical Goal
This fork targets a devirtualized output that:
- preserves original runtime behavior,
- starts without native runtime crashes,
- remains executable after method replacement.

## Build
### Requirements
- Windows x64 (tested/recommended)
- `.NET SDK 8.0 or newer`

### Recommended build
From repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-all.ps1 -Configuration Release
```

The script performs:
1. restore for main projects,
2. build for `Krypton.Core` and `Krypton.Pipeline`,
3. serial build for `Krypton` launcher (to avoid intermittent static-graph MSBuild restore/build edge cases).

### Manual build (Release Rebuild)
```powershell
dotnet build .\Krypton.Core\Krypton.Core.csproj -c Release -t:Rebuild
dotnet build .\Krypton.Pipeline\Krypton.Pipeline.csproj -c Release -t:Rebuild
dotnet msbuild .\Krypton\Krypton.csproj /t:Rebuild /p:Configuration=Release /m:1
```

One-liner equivalent:
```powershell
dotnet build .\Krypton.Core\Krypton.Core.csproj -c Release -t:Rebuild; dotnet build .\Krypton.Pipeline\Krypton.Pipeline.csproj -c Release -t:Rebuild; dotnet msbuild .\Krypton\Krypton.csproj /t:Rebuild /p:Configuration=Release /m:1
```

## Run
```powershell
dotnet .\Krypton\bin\Release\net8.0\Krypton.dll <input-assembly.exe> --no-pause
```

or:

```powershell
.\Krypton\bin\Release\net8.0\Krypton.exe <input-assembly.exe> --no-pause
```

### Drag and drop usage (Windows)
You can drag a target `.exe` (or `.dll`) file directly onto `Krypton.exe`.
Krypton receives the dropped file path as argument and runs devirtualization for that input.

## Output
For `sample.exe`:
- patched output: `sample-Devirtualized.exe`
- report: `sample-Devirtualized-report.txt`

## Useful Environment Variables
### UX / logging
- `KRYPTON_NO_PAUSE=1`
- `KRYPTON_LOG_VM_MAP=1`
- `KRYPTON_LOG_LOCAL_TYPES=1`
- `KRYPTON_LOG_EXCEPTIONS=1`

### Mapping behavior
- `KRYPTON_ENABLE_AGGRESSIVE_LAST_RESORT=1` (enables aggressive tie-breaks in rare-opcode inference; default is strict/safety-first)

### Runtime stabilization
- `KRYPTON_DISABLE_HASHTABLE_SANITIZE=1`
- `KRYPTON_DISABLE_WINFORMS_GUARD_BYPASS=1`
- `KRYPTON_DISABLE_STRING_ANTI_MANIPULATION_PATCH=1`
- `KRYPTON_DISABLE_SHARED_BOOTSTRAP_NEUTRALIZE=1`
- `KRYPTON_DISABLE_STARTUP_GUARD=1`
- `KRYPTON_DISABLE_ALL_BOOTSTRAP_CCTORS=1`

### Hidden-call recovery and cleanup
- `KRYPTON_HCR_ENABLE=0` (disables `HiddenCallRecovery`; on by default)
- `KRYPTON_CLEAN_ENABLE=0` (master kill-switch for `PostDeobfuscation`; on by default)
- `KRYPTON_STRING_DECRYPT=1` (enables `StringDecryption`; off by default)
- `KRYPTON_RESOURCE_DECRYPT=1` (enables `ResourceDecryption`; off by default)

### Write / patch behavior
- `KRYPTON_ALLOW_PARTIAL_OUTPUT=1` (allows writing when some VM opcodes remain unresolved)
- `KRYPTON_ALLOW_STABILIZATION_ONLY_OUTPUT=1` (allows output even with zero recompiled methods, applying only stabilization patches)
- `KRYPTON_USE_INPLACE_PATCH=1` (forces in-place patch mode instead of default rewrite mode)
- `KRYPTON_STRIP_MALFORMED_ATTRIBUTES=1`

## Auxiliary Tooling (`tools/`)
The repository includes helper utilities for pattern and runtime investigation:
- `PatternProbe`
- `HandlerDump`
- `MethodFullDump`
- `MethodBodyPayloadProbe`
- `ProtectionMap`

These tools help during opcode mapping extension, payload-body inspection, and protection-regression analysis.

## Known Limitations
- Not all Reactor families are fully covered; mapping still depends on observable handler patterns.
- If unknown VM bytes remain, affected methods are intentionally skipped (safety-first).
- Some Reactor patterns still use semantic hints from internal calls; further generalization toward signature + data-flow matching is possible.

## Recommended Roadmap
1. Fully generalize pattern verification (less name-based hints, more signature/data-flow based matching).
2. Extend coverage for remaining opcodes in very large methods (for example `<Module>` and complex UI flows).
3. Add automated multi-sample test matrix (build + devirt + smoke-run).
4. Add before/after metrics export for objective validation.

## Disclaimers
This project is intended for research, interoperability, and technical understanding of virtualized/obfuscated code in lawful contexts.
