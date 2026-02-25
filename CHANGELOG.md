# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.3.0] - 2026-02-25

### Security
- Added Zip Slip (path traversal) protection for ZIP extraction in `--slug` mode
- All ZIP entries are now validated to resolve within the target directory before extraction
- Maliciously crafted ZIP archives with `../` path traversal entries are rejected with a security error

## [1.2.0] - 2026-02-25

### Changed
- Replaced `--slug` mode implementation from `npx clawhub@latest install` to pure Python using `urllib` + `zipfile`
- Removed all Node.js / npm / clawhub CLI dependencies
- Scanner now has zero external dependencies — uses only Python standard library

### Fixed
- Fixed browser control service error caused by npx spawning background processes

## [1.1.0] - 2026-02-25

### Added
- `--slug` mode to download and scan skills directly from ClawHub without prior local installation
- `--version` flag to scan a specific version of a ClawHub skill
- ClawHub REST API integration (`/api/v1/skills/<slug>`, `/api/v1/download`)
- Automatic temporary directory cleanup after remote scan

## [1.0.0] - 2026-02-25

### Added
- Initial release
- Automated static analysis scanner (`scan_skill.py`) with 60+ malicious pattern rules
- Three severity levels: HIGH, MEDIUM, LOW with pattern-based detection
- Structural integrity checks (SKILL.md validation, suspicious file types, file size limits)
- SHA-256 file hash inventory for integrity verification
- Threat knowledge base (`threat_knowledge_base.md`) documenting the ClawHavoc supply chain attack
- SKILL.md with 5-step security audit workflow for OpenClaw integration
- Deduplication of findings to avoid redundant alerts
- JSON structured report output to stdout
