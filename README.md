<div align="center">
  <img src="assets/icon.png" width="132" alt="BLACKBOX icon">
  <h1>BLACKBOX</h1>
  <p><strong>Local repository forensics for structure, hotspots, risks, dependencies, and suspicious code patterns.</strong></p>
  <p>
    <a href="https://github.com/purysho/BLACKBOX/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/purysho/BLACKBOX/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/purysho/BLACKBOX/releases"><img alt="Releases" src="https://img.shields.io/github/v/release/purysho/BLACKBOX?display_name=tag&sort=semver"></a>
    <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-202832.svg"></a>
    <a href="#download"><img alt="Status: beta" src="https://img.shields.io/badge/status-beta-C9A44C.svg"></a>
  </p>
  <p><strong>Download:</strong> <a href="https://github.com/purysho/BLACKBOX/releases/latest/download/BLACKBOX-Windows-x64.exe">Windows</a> · <a href="https://github.com/purysho/BLACKBOX/releases/latest/download/BLACKBOX-macOS-arm64.zip">macOS</a> · <a href="https://github.com/purysho/BLACKBOX/releases/latest/download/BLACKBOX-Linux-x86_64.tar.gz">Linux</a> · <a href="#run-from-source">Run from source</a> · <a href="https://github.com/purysho/BLACKBOX/issues">Report an issue</a></p>
</div>

![BLACKBOX scanning a repository: risk score, file and line counts, and the language overview](docs/screenshot.png)

## What it does

- Repository structure and language mix
- Large files and code hotspots
- TODO/FIXME-style findings and suspicious-pattern signals
- Dependency and cycle signals
- Git repository context
- Exportable JSON reports

## Download

| Platform | File |
|---|---|
| Windows 10/11 (x64) | [BLACKBOX-Windows-x64.exe](https://github.com/purysho/BLACKBOX/releases/latest/download/BLACKBOX-Windows-x64.exe) — portable, no installer |
| macOS (Apple Silicon) | [BLACKBOX-macOS-arm64.zip](https://github.com/purysho/BLACKBOX/releases/latest/download/BLACKBOX-macOS-arm64.zip) — unzip and move to Applications |
| Linux (x86_64) | [BLACKBOX-Linux-x86_64.tar.gz](https://github.com/purysho/BLACKBOX/releases/latest/download/BLACKBOX-Linux-x86_64.tar.gz) — extract and run `./BLACKBOX` |

Each [release](https://github.com/purysho/BLACKBOX/releases) is built from the tagged source by GitHub Actions and carries a `SHA256SUMS.txt`. The builds are not yet code-signed, so on first launch Windows SmartScreen may ask you to confirm ("More info" → "Run anyway"), and macOS may need you to Control-click the app and choose **Open**.

**Status: beta.** BLACKBOX does what this README describes and is covered by CI on Windows, macOS and Linux, but it is young: expect rough edges, and please [report them](https://github.com/purysho/BLACKBOX/issues).

## Run from source

Requirements: Python 3.10+ with Tk support.

```powershell
pyw blackbox_desktop.pyw
```

The application uses Python's standard library at runtime.

## Build a standalone Windows executable

```powershell
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

Output:

```text
dist\BLACKBOX.exe
```

## Privacy

Scanning happens locally. BLACKBOX does not require an account, backend, or source-code upload.

## Scope

BLACKBOX is a first-pass forensic view, not a compiler-grade static analyzer. Findings are investigation signals rather than proof that code is unsafe or defective.

## Release process

- Every push runs tests/compile checks and builds a Windows executable artifact.
- Tags matching `v*` build the executable again, compute SHA256, and publish both files to GitHub Releases.
- See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT
