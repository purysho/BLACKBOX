# Changelog

All notable changes to BLACKBOX are documented here.

## [1.2.0] - 2026-09-26

### Added
- Release builds for macOS (Apple Silicon) and Linux (x86_64) alongside Windows, with one `SHA256SUMS.txt` per release.
- A `--repo PATH` argument that opens BLACKBOX on a repository and starts a scan, used by Switchyard's tool handoff.
- The application icon, which the Windows executable was missing.
- A screenshot of the running app in the README.

### Changed
- CI builds the macOS and Linux packages on every push.

## [1.1.0] - 2026-09-16

### Added
- Polished public release documentation and screenshot.
- Cross-platform CI checks plus Windows executable build artifact.
- Automated tagged GitHub Release workflow with SHA256 checksum.
- Issue templates and security/reporting guidance.

### Current product
- Repository structure and language mix
- Large files and code hotspots
- TODO/FIXME-style findings and suspicious-pattern signals
- Dependency and cycle signals
- Git repository context
- Exportable JSON reports
