# Architecture: Reverse-Engineering CTF Challenge Solver Toolkit (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Integrated reverse-engineering workspace for CTF challenges spanning static disassembly, dynamic debugging, string/entropy analysis, cryptographic helper utilities, and multi-format writeup export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Reverse-Engineering CTF Solver Toolkit (RECT)** is a GUI-driven desktop application that consolidates the disassemblers, debuggers, and helper utilities that CTF players typically juggle across a dozen terminal windows during reverse-engineering challenges. It provides a unified workspace for static analysis (disassembly, decompilation, string extraction), dynamic analysis (debugging, memory inspection), cryptographic helpers (hash identification, encoding/decoding), and structured writeup generation.

CTF reverse engineering challenges span a wide range: simple flag-check binaries with hardcoded comparisons, obfuscated code with custom VM interpreters, packed/encrypted binaries, and crypto-based challenges requiring key recovery. Players currently chain Ghidra, x64dbg, CyberChef, `binwalk`, `strings`, and a Python REPL. Each tool has its own workflow, and context switching is the primary source of wasted time during a timed event.

The tool is designed around four principles:

1. **One challenge, one workspace** — everything for a challenge lives in a single case directory: binaries, notes, extracted artifacts, and the final writeup.
2. **Tool orchestration, not replacement** — the toolkit wraps best-in-class tools (Ghidra headless, radare2, `capstone`, `angr`) rather than reimplementing them.
3. **Reproducible solving** — every step is logged; scripts and commands can be replayed to regenerate the solution.
4. **Writeup-ready** — export a complete writeup in Markdown, HTML, or PDF with screenshots, code snippets, and command history.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Challenge │ │ Static    │ │ Dynamic   │ │ Crypto    │ │ Writeup │ │
│  │ Workspace │ │ Analysis  │ │ Debugger  │ │ Helpers   │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Hex       │ │ Disasm /  │ │ Memory    │ │ String    │ │ Console │ │
│  │ Viewer    │ │ Decompile │ │ Inspector │ │ Analyzer  │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Challenge  │ │ Tool       │ │ Script     │ │ Event Bus / Log    │ │
│  │ Controller │ │ Orchestr.  │ │ Runner     │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Analysis Engine Layer                            │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Binary Loader  │ │ Disassembler   │ │ Decompiler               │  │
│  │ (ELF/PE/Mach-O)│ │ (Capstone)     │ │ (Ghidra headless /       │  │
│  │                │ │                │ │  r2 / RetDec)            │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Debugger       │ │ Symbolic       │ │ Crypto / Encoding        │  │
│  │ (ptrace/GDB)   │ │ Executor       │ │ Toolkit                  │  │
│  │                │ │ (angr)         │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Challenge  │ │ Artifact   │ │ Script     │ │ Writeup Store      │ │
│  │ Store      │ │ Store      │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `ChallengeWorkspaceView` | Create/open a challenge case: challenge name, category, event, description, flag format. Display case directory tree (binaries, notes, artifacts). |
| `StaticAnalysisView` | **Primary static view.** Disassembly listing with syntax highlighting, cross-references, function list, symbol table. Toggle between disassembly and decompiled pseudo-C. |
| `HexViewerView` | Hex dump with ASCII column, structure overlay (ELF/PE headers), search, byte pattern matching. |
| `DynamicDebuggerView` | **Primary dynamic view.** Debugger controls (step, continue, breakpoints), register panel, stack panel, memory viewer, disassembly with execution pointer. |
| `MemoryInspectorView` | Memory map (regions, permissions), live memory viewer, string search in memory, dump to file. |
| `StringAnalyzerView` | Extracted strings with encoding (ASCII/UTF-8/UTF-16), suspicious pattern classification (URLs, base64, format strings), entropy heatmap. |
| `CryptoHelpersView` | Encoding/decoding toolbox: base64, hex, URL, ROT13, XOR (brute-force + known-key), hash identification, RSA parameter inspection . |
| `SymbolicExecView` | Configure and run `angr`-based symbolic execution to find input that reaches a target address. |
| `ScriptRunnerView` | Python REPL scoped to the challenge context; run snippets against loaded binary; save reusable scripts. |
| `NotesPanel` | Per-challenge notes with Markdown support; auto-linked to evidence. |
| `WriteupBuilderView` | **Export interface.** Assemble writeup from notes, screenshots, command history, code snippets. Format selection (Markdown, HTML, PDF). |
| `ConsoleView` | Live log: tool invocations, disassembler warnings, debugger output, errors. |

**Key UI Patterns:**
- **Multi-pane layout**: disassembly/decompilation on the left, hex/strings on the right, bottom console; panes are dockable and resizable.
- **Cross-reference navigation**: click a symbol → jump to definition; click an address → jump to disassembly.
- **Execution highlighting**: in debug mode, the current instruction and stack/register state update live.
- **Evidence capture**: one-click "add to writeup" for any pane content (with timestamp and context).
- **Command replay**: every tool invocation is logged and replayable.

### 3.2 Orchestration Layer

**Challenge Controller**
- Manages challenge lifecycle: create case → load binary → analyze → solve → writeup.
- Maintains case directory structure and metadata.
- Tracks progress and flag submission status.

**Tool Orchestrator**
- Wraps external tools (Ghidra headless, radare2, GDB, `binwalk`, `upx`) as subprocesses or libraries.
- Manages tool output parsing and caching.
- Handles tool version detection and capability negotiation.

**Script Runner**
- Provides a Python REPL with access to the loaded binary, extracted artifacts, and helper functions.
- Executes in a sandboxed subprocess for safety.
- Logs all executed scripts for replay.

### 3.3 Analysis Engine Layer

**Binary Loader**
- Supports ELF, PE, Mach-O, and raw binaries.
- Uses `lief` for parsing headers, sections, imports, exports, relocations.
- Detects architecture (x86, x64, ARM, MIPS, RISC-V), endianness, and bitness.
- Detects packing/encryption via entropy analysis and section anomalies.

**Disassembler**
- Uses `capstone` for multi-architecture disassembly.
- Uses `radare2` (via `r2pipe`) for advanced analysis (function detection, xrefs, basic blocks).
- Supports syntax variants (Intel, AT&T).

**Decompiler**
- Uses Ghidra headless (`analyzeHeadless`) for pseudo-C decompilation.
- Alternative: radare2's `pdc` command for lightweight decompilation.
- Caches decompiled output per function.

**Debugger**
- Uses `ptrace` on Linux, `pygdbmi` for GDB/MI interface on all platforms.
- Supports breakpoints, single-step, continue, register/memory inspection.
- Handles signal delivery for anti-debug challenges.
- Detects common anti-debugging techniques (ptrace self-attach, `/proc/self/status` checks) .

**Symbolic Executor**
- Wraps `angr` for finding inputs that reach target addresses (flag-check bypass).
- Configurable target address, avoid addresses, input constraints.
- Reports candidate solutions.

**Crypto / Encoding Toolkit**
- Hash identification (`hashid`, `haiti`) .
- Encoding/decoding: base64, base32, hex, URL, ROT13, Caesar, Vigenère.
- XOR analysis: single-byte brute force, key-length detection, known-plaintext.
- RSA helper: parse PEM/DER keys, factor small moduli, compute `d`, decrypt ciphertext.
- Classical ciphers: substitution, transposition, rail fence.

### 3.4 Storage Layer

**Data directory:**
```
~/.rect/
├── challenges/
│   └── <challenge_id>/
│       ├── challenge.json       # Metadata (name, category, event, flag format)
│       ├── binary/              # Loaded binary (read-only reference)
│       ├── artifacts/           # Extracted files, decrypted blobs
│       ├── notes/               # Markdown notes
│       ├── scripts/             # Saved Python snippets
│       ├── screenshots/         # Evidence captures
│       ├── command_log.jsonl    # All tool invocations
│       └── writeup/
│           ├── writeup.md
│           ├── writeup.html
│           └── writeup.pdf
└── logs/
    └── rect.log
```

**Challenge record model:**
```python
@dataclass
class Challenge:
    challenge_id: str
    name: str
    category: str                  # 'rev', 'crypto', 'pwn', 'misc'
    event: str | None
    description: str
    flag_format: str | None        # e.g., 'flag{...}'
    binary_path: str
    architecture: str              # 'x86_64', 'arm', 'mips'
    file_type: str                 # 'elf', 'pe', 'macho'
    packed: bool
    solved: bool
    flag: str | None
    notes_md: str
    created_at: datetime

@dataclass
class CommandLog:
    timestamp: datetime
    tool: str                      # 'r2', 'ghidra', 'gdb', 'angr', 'script'
    command: str
    output_summary: str
    duration_ms: int
```

### 3.5 Canonical Data Model

See `Challenge` and `CommandLog` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, disassembly rendering, debugger state
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Analysis Worker Pool (QThreadPool, N workers)
  ├── Disassembly threads
  ├── Decompilation threads (Ghidra headless)
  ├── String extraction threads
  └── Symbolic execution threads

Debugger Thread (single)
  ├── ptrace/GDB control
  ├── Breakpoint management
  └── Event marshalling

Script Sandbox (subprocess)
  └── Isolated Python execution
```

**Rules:**
- Ghidra headless runs as a subprocess (long-running; cached output).
- Debugger runs in dedicated thread; UI marshalled via signals.
- Symbolic execution (`angr`) can be long-running; runs in worker with cancellation.
- Script runner executes in sandboxed subprocess; output streamed back.

---

## 5. Workflow: End-to-End User Journey

1. **Create Challenge** → name, category, event, flag format.
2. **Load Binary** → drag/drop binary; auto-detect architecture, file type, packing.
3. **Static Analysis** → disassemble, decompile, inspect functions, strings, symbols.
4. **Identify Logic** → find flag-check routine, crypto routine, or hidden data.
5. **Dynamic Analysis** (if needed) → set breakpoints, step through, inspect memory.
6. **Crypto/Encoding** → decode obfuscated strings, decrypt blobs, recover keys.
7. **Symbolic Execution** (if needed) → run `angr` to solve for input.
8. **Recover Flag** → validate flag format; mark challenge solved.
9. **Capture Evidence** → screenshots, code snippets, command history.
10. **Build Writeup** → assemble notes and evidence into Markdown/HTML/PDF.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Malicious challenge binary** | Run in isolated lab VM; never execute on host without warning; debugger runs with reduced privileges. |
| **Script execution** | Script runner sandboxed in subprocess; resource limits; no network access by default. |
| **Tool supply-chain** | Bundle or verify hashes of external tools (radare2, Ghidra, GDB). |
| **Anti-analysis evasion** | Detect anti-debugging techniques; provide bypass guidance; document limitations. |
| **Data exfiltration** | No network access by default; external lookups (CyberChef API) disabled. |
| **Writeup leakage** | Writeups contain flags and solutions; local-only; optional encryption at rest. |

---

## 7. Extensibility Points

1. **New disassembler backend** — implement `DisassemblerBackend` ABC (Capstone, radare2, objdump).
2. **New decompiler backend** — implement `DecompilerBackend` ABC (Ghidra, RetDec, r2).
3. **New crypto helper** — add to `CryptoHelpers` registry.
4. **New symbolic execution engine** — implement `SymbolicEngine` ABC (angr, Manticore).
5. **New export format** — `Exporter` ABC (Markdown, HTML, PDF).

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 3 s |
| Binary load (10 MB) | < 2 s |
| Disassembly (10k instructions) | < 3 s |
| Ghidra headless decompilation | < 60 s |
| Debugger step latency | < 100 ms |
| String extraction (10 MB) | < 2 s |
| Symbolic execution | < 5 min (configurable timeout) |
| Memory footprint | < 1 GB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Binary parsing | `lief` | Multi-format, modern |
| Disassembly | `capstone` + `r2pipe` (radare2) | Multi-arch, mature |
| Decompilation | Ghidra headless | Best-in-class pseudo-C |
| Debugger | `pygdbmi` (GDB/MI), `ptrace` | Cross-platform |
| Symbolic execution | `angr` | Standard for CTF |
| Crypto helpers | `pycryptodome`, `hashid`, `sympy` | Standard libraries |
| Script runner | Sandboxed `subprocess` (Python) | Isolation |
| Report export | `markdown`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
rect/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── rect/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── challenge_workspace.py
│       │   │   ├── static_analysis.py
│       │   │   ├── hex_viewer.py
│       │   │   ├── dynamic_debugger.py
│       │   │   ├── memory_inspector.py
│       │   │   ├── string_analyzer.py
│       │   │   ├── crypto_helpers.py
│       │   │   ├── symbolic_exec.py
│       │   │   ├── script_runner.py
│       │   │   ├── writeup_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── functions_table_model.py
│       │   │   └── strings_table_model.py
│       │   └── widgets/
│       │       ├── disasm_pane.py
│       │       ├── register_panel.py
│       │       ├── stack_panel.py
│       │       └── evidence_button.py
│       ├── core/
│       │   ├── loader/
│       │   │   └── binary_loader.py
│       │   ├── disasm/
│       │   │   ├── capstone_backend.py
│       │   │   └── r2_backend.py
│       │   ├── decompile/
│       │   │   ├── ghidra_backend.py
│       │   │   └── r2_backend.py
│       │   ├── debugger/
│       │   │   ├── gdb_backend.py
│       │   │   └── ptrace_backend.py
│       │   ├── symbolic/
│       │   │   └── angr_backend.py
│       │   ├── crypto/
│       │   │   ├── encoding.py
│       │   │   ├── xor.py
│       │   │   ├── hash_id.py
│       │   │   └── rsa.py
│       │   └── script/
│       │       └── sandbox.py
│       ├── storage/
│       │   ├── challenge_store.py
│       │   ├── artifact_store.py
│       │   └── command_log.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── markdown_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── hashing.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── themes/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, challenge workspace, binary loader (`lief`) | 2 weeks |
| **P1 — Static Analysis** | Capstone disassembly, hex viewer, function list | 3 weeks |
| **P2 — Strings & Entropy** | String extraction, classification, entropy heatmap | 1 week |
| **P3 — Crypto Helpers** | Encoding/decoding, XOR brute force, hash ID | 2 weeks |
| **P4 — Decompilation** | Ghidra headless integration, pseudo-C view | 2 weeks |
| **P5 — Dynamic Debugger** | GDB/MI integration, breakpoints, register/stack panels | 3 weeks |
| **P6 — Symbolic Execution** | angr integration, target/avoid addresses | 2 weeks |
| **P7 — Script Runner** | Sandboxed Python REPL, challenge context API | 1 week |
| **P8 — Writeup Builder** | Notes, evidence capture, Markdown/HTML/PDF export | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~21 weeks (single senior dev) / ~11 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: binary parsing, disassembly correctness, XOR brute force, encoding/decoding.
- **Integration**: full workflow on public CTF challenges (picoCTF, HackTheBox reversing, CTFtime archives).
- **GUI**: `pytest-qt` for disasm pane, debugger, crypto helpers.
- **Cross-validation**: compare disassembly against objdump/Ghidra; compare decompilation against source when available.
- **Safety**: verify script sandbox isolation; verify no host execution without warning.

---

## 13. Open Questions / Decisions Pending

1. **Ghidra dependency** — Ghidra is heavyweight (Java, ~1 GB). Recommend: optional; detect and prompt; use r2 decompiler as fallback.
2. **Debugger on Windows** — `ptrace` is Linux-only; Windows requires `pygdbmi` + GDB or WinDbg. Recommend: GDB/MI for cross-platform.
3. **angr performance** — symbolic execution can be slow; recommend strict timeouts and clear UI feedback.
4. **Script sandbox level** — full isolation (separate VM) vs. subprocess with resource limits. Recommend: subprocess with `resource` limits for v1.

---

## 14. Glossary

- **CTF** — Capture The Flag; security competition.
- **Reverse Engineering** — Analyzing a binary to understand its behavior.
- **Disassembly** — Converting machine code to assembly.
- **Decompilation** — Converting machine code to high-level pseudo-code.
- **Capstone** — Multi-architecture disassembly framework.
- **radare2** — Reverse-engineering framework with `r2pipe` Python API.
- **Ghidra** — NSA's reverse-engineering suite with headless mode.
- **angr** — Symbolic execution framework for binary analysis.
- **Anti-debugging** — Techniques that detect or prevent debugging.
- **Packing** — Compressing/encrypting a binary to hinder analysis.
- **Flag** — The prize string in a CTF challenge.

---

*End of document.*