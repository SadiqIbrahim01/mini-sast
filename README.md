# 🔐 Mini SAST

> A production-grade Static Application Security Testing (SAST) tool built in Java 21.
> Finds security vulnerabilities via **AST analysis** — not regex.

[![CI](https://github.com/SadiqIbrahim01/mini-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/SadiqIbrahim01/mini-sast/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-21-orange?logo=openjdk)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3-brightgreen?logo=springboot)](https://spring.io/projects/spring-boot)
[![Maven](https://img.shields.io/badge/Maven-3.9-blue?logo=apache-maven)](https://maven.apache.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](https://github.com/SadiqIbrahim01/mini-sast/pkgs/container/mini-sast)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Detects

| Rule | Vulnerability | Severity | CWE | Technique |
|---|---|---|---|---|
| JAVA-SQL-001 | SQL Injection (direct) | 🔴 CRITICAL | CWE-89 | AST pattern matching |
| JAVA-SQL-002 | SQL Injection (aliased) | 🔴 CRITICAL | CWE-89 | Taint flow analysis |
| JAVA-SEC-001 | Hardcoded Secrets | 🟠 HIGH | CWE-798 | Shannon entropy + patterns |
| JAVA-CMD-001 | Command Injection | 🔴 CRITICAL | CWE-78 | AST pattern matching |
| CONFIG-SEC-001 | Secrets in Config Files | 🔴 CRITICAL | CWE-798 | Reference vs. value detection |

**Validated:** 186 files scanned on an unfamiliar third-party codebase → 3 real findings, 0 false positives.

---

## Why AST, Not Regex

Most security linters are glorified `grep` commands. Mini SAST parses your code into an
**Abstract Syntax Tree** — the same structure a compiler uses — and analyses it structurally.

```java
// A regex scanner fires on ALL of these (false positives):
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId); // vulnerable ✅
// stmt.executeQuery("SELECT ...") -- commented out             // false positive ❌
String x = "Call executeQuery( for reads";                     // false positive ❌

// Mini SAST fires ONLY on the first line — it understands code structure.
```

The result: zero false positives on real codebases.

---

## Three Ways to Use It

### 1. Docker (zero setup required)

```bash
docker pull ghcr.io/sadiqibrahim01/mini-sast:latest

# Scan a project
docker run --rm \
  -v /path/to/your/project:/scan:ro \
  ghcr.io/sadiqibrahim01/mini-sast:latest \
  scan /scan --severity HIGH

# Generate an HTML report
docker run --rm \
  -v /path/to/your/project:/scan:ro \
  -v $(pwd):/output \
  ghcr.io/sadiqibrahim01/mini-sast:latest \
  scan /scan --output html --output-file /output/report.html
```

### 2. CLI (requires Java 21+)

Download the JAR from [GitHub Releases](https://github.com/SadiqIbrahim01/mini-sast/releases).

```bash
# Basic scan
java -jar mini-sast-cli-0.1.0-SNAPSHOT-standalone.jar scan ./src

# Only report HIGH severity and above
java -jar mini-sast-cli-*.jar scan ./src --severity HIGH

# Save JSON report
java -jar mini-sast-cli-*.jar scan ./src --output json --output-file report.json

# Save HTML report (open in browser)
java -jar mini-sast-cli-*.jar scan ./src --output html --output-file report.html

# Fail with exit code 1 if findings exist (for CI/CD pipelines)
java -jar mini-sast-cli-*.jar scan ./src --severity MEDIUM --fail-on-findings
```

### 3. REST API

```bash
# Start the API server
java -jar mini-sast-api-0.1.0-SNAPSHOT.jar

# Trigger a scan via HTTP
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: your-api-key" \
  -d '{"target":"/path/to/project","minimumSeverity":"HIGH"}'

# Open the web dashboard
open http://localhost:8080
```

---

## CI/CD Integration

Add this to your GitHub Actions workflow to block deployments on security findings:

```yaml
- name: Run Mini SAST Security Scan
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/scan:ro \
      ghcr.io/sadiqibrahim01/mini-sast:latest \
      scan /scan \
      --severity MEDIUM \
      --fail-on-findings

- name: Upload Security Report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: sast-report
    path: sast-report.json
```

---

## Sample Output

### CLI