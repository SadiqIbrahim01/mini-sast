# 🔐 Mini SAST

> A production-grade Static Application Security Testing (SAST) tool built in Java 21.  
> Finds security vulnerabilities via **AST analysis** — not regex.

[![CI](https://github.com/SadiqIbrahim01/mini-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/mini-sast/actions)
[![Java](https://img.shields.io/badge/Java-21-orange?logo=openjdk)](https://openjdk.org/projects/jdk/21/)
[![Maven](https://img.shields.io/badge/Maven-3.9-blue?logo=apache-maven)](https://maven.apache.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What Mini SAST Detects

| Vulnerability        | Severity | CWE      | Status      |
|----------------------|----------|----------|-------------|
| SQL Injection        | CRITICAL | CWE-89   | 🔜 Phase 2  |
| Hardcoded Secrets    | HIGH     | CWE-798  | 🔜 Phase 2  |
| Command Injection    | CRITICAL | CWE-78   | 🔜 Phase 2  |
| Unsafe Deserialization | HIGH   | CWE-502  | 🔜 Phase 2  |
| Path Traversal       | HIGH     | CWE-22   | 🔜 Phase 2  |

---

## Quick Start

### CLI

```bash
# Build
mvn clean package -pl cli -am

# Scan a directory
java -jar cli/target/mini-sast-cli-0.1.0-SNAPSHOT-standalone.jar scan ./src

# Scan with minimum severity filter
java -jar cli/target/mini-sast-cli-*-standalone.jar scan ./src --severity HIGH

# Fail CI if findings exist (for pipelines)
java -jar cli/target/mini-sast-cli-*-standalone.jar scan ./src --fail-on-findings
```

### Docker *(coming Phase 6)*

```bash
docker pull ghcr.io/YOUR_USERNAME/mini-sast:latest
docker run --rm -v $(pwd):/scan mini-sast scan /scan
```

### CI Integration *(GitHub Actions)*

```yaml
- name: Run Mini SAST
  run: |
    java -jar mini-sast-cli.jar scan ./src \
      --severity MEDIUM \
      --fail-on-findings \
      --output json \
      --output-file sast-report.json
```

---

## Architecture

Mini SAST is a **multi-module Java 21** project with clean separation of concerns:

The `core` module has **zero framework dependencies**. It can be embedded in any Java application, called from tests, or wrapped in any interface.

Key design decisions:
- **AST over regex** — structured analysis, not text matching
- **Pluggable rules** — add new rules without touching the engine
- **Multi-language architecture** — Java first, extensible to Python/JS
- **Immutable findings** — scan results are value objects, safe to cache/share

See [docs/architecture.md](docs/architecture.md) for the full design.

---

## Development

```bash
# Clone
git clone https://github.com/SadiqIbrahim01/mini-sast.git
cd mini-sast

# Build all modules
mvn clean verify

# Run tests only
mvn test

# Build CLI fat JAR
mvn clean package -pl cli -am
```

**Requirements:** Java 21, Maven 3.9+

---

## Roadmap

- [x] Phase 1: Architecture & Foundation
- [ ] Phase 2: Core Detection Engine (SQL injection, secrets, command injection)
- [ ] Phase 3: Taint Analysis (source → sink tracking)
- [ ] Phase 4: Rich Reporting (JSON, HTML, PDF)
- [ ] Phase 5: Developer Experience (config files, rule customization)
- [ ] Phase 6: Docker + CI/CD pipeline
- [ ] Phase 7: REST API + Web Dashboard
- [ ] Phase 8: Documentation & Threat Model

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions welcome.

---

## License

[MIT](LICENSE)