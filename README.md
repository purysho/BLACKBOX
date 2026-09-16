<div align="center">
  <img src="assets/icon.svg" width="140" alt="BLACKBOX icon">
  <h1>BLACKBOX</h1>
  <p><strong>Local repository forensics for structure, hotspots, risks, dependencies, and suspicious code patterns.</strong></p>
</div>

BLACKBOX is a lightweight Windows desktop scanner for quickly understanding an unfamiliar software repository. Choose a folder, run a local scan, inspect the results, and export a JSON report. No source code is uploaded anywhere.

## What it shows

- Repository structure and language mix
- Large files and code hotspots
- TODO/FIXME-style findings and suspicious patterns
- Dependency signals
- Git repository information when available
- Exportable JSON scan reports

## Why it exists

Large codebases are hard to orient around quickly. BLACKBOX is intended as a fast first-pass forensic view before deeper review, refactoring, debugging, or security work.

## Run from source

Requirements: Windows and Python 3.10+.

```powershell
pyw blackbox_desktop.pyw
```

The application uses Python's standard library and Tkinter; there are no third-party runtime dependencies.

## Build a standalone Windows executable

```powershell
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

The build script creates:

```text
dist\BLACKBOX.exe
```

## Project structure

```text
BLACKBOX/
├── blackbox_core/
│   └── scanner.py       # deterministic repository scanner
├── blackbox_desktop.pyw # Tkinter desktop interface
├── build-windows.ps1    # Windows EXE build helper
├── assets/
└── .github/workflows/
```

## Privacy

BLACKBOX is local-first. Scanning is performed on the machine running the application; the app does not require an account, cloud backend, or network service.

## Current scope

BLACKBOX is deliberately a first-pass scanner rather than a compiler-grade static analyzer. Findings are signals for investigation, not proof that code is unsafe or defective.

## Status

V1.1 — usable Windows desktop build with core scanning and JSON export.
