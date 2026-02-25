# skill-security-audit

Comprehensive security risk assessment tool for [ClawHub](https://clawhub.ai) skills. Detect prompt injection, malicious scripts, supply chain attacks, credential theft, and other threats before installation — informed by real-world attack cases like the ClawHavoc campaign.

## Features

- **60+ malicious pattern detection** — covers RCE, Base64 obfuscation, reverse shells, credential theft, persistence mechanisms, prompt injection, and more
- **Two scan modes** — scan a local skill directory or download directly from ClawHub via `--slug`
- **Zero external dependencies** — pure Python standard library (`urllib`, `zipfile`, `re`, `hashlib`)
- **Structured JSON report** — severity-classified findings, file integrity inventory with SHA-256 hashes
- **Threat knowledge base** — reference documentation based on the ClawHavoc supply chain attack

## Quick Start

### Scan a local skill directory

```bash
python3 scripts/scan_skill.py /path/to/skill-directory
```

### Scan a skill from ClawHub (not yet installed)

```bash
python3 scripts/scan_skill.py --slug stock-price-query
```

### Scan a specific version

```bash
python3 scripts/scan_skill.py --slug stock-price-query --version 1.0.3
```

## Usage as OpenClaw Skill

This project is designed to be used as a skill in [OpenClaw](https://clawhub.ai). Once installed, the AI agent will:

1. Determine the skill source (local path, slug, or ClawHub URL)
2. Run the automated static analysis scanner
3. Perform expert review of SKILL.md for prompt injection and hidden directives
4. Review all scripts and code files for obfuscation, network behavior, and sensitive access
5. Generate a structured security assessment report with risk rating

## Report Format

The scanner outputs a JSON report containing:

- **scan_metadata** — timestamp, tool version, scanned path
- **summary** — total findings count, breakdown by severity (CRITICAL / HIGH / MEDIUM / LOW)
- **findings** — each finding with severity, category, message, file, line number, and matched text
- **file_inventory** — SHA-256 hashes and sizes of all files for integrity verification

## Risk Rating Criteria

| Level | Description |
|-------|-------------|
| **CRITICAL** | Active exploit patterns (RCE chains, credential theft, reverse shells, confirmed prompt injection) |
| **HIGH** | Dangerous patterns that could be weaponized (curl\|bash, eval/exec, sensitive path access) |
| **MEDIUM** | Suspicious patterns with both legitimate and malicious use cases |
| **LOW** | Minor informational findings (non-standard URLs, code quality markers) |
| **SAFE** | No findings or only LOW-severity items with clear legitimate purpose |

## Project Structure

```
skill-security-audit/
├── SKILL.md                            # OpenClaw skill definition & workflow
├── README.md                           # This file
├── CHANGELOG.md                        # Version history
├── scripts/
│   └── scan_skill.py                   # Automated static analysis scanner
└── references/
    └── threat_knowledge_base.md        # Threat intelligence knowledge base
```

## Requirements

- Python 3.10+
- No external packages required

## License

MIT
