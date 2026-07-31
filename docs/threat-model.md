# Mini SAST — Threat Model

## What This Document Is

This analyses the security of Mini SAST **itself** — not the
vulnerabilities it finds. A SAST tool processes untrusted input
(arbitrary source code) and exposes a network API. Both surfaces
need deliberate hardening.

---

## Threat 1: Memory Exhaustion via Crafted Source File

**The attack:**
An attacker commits a Java file specifically designed to make
JavaParser consume enormous memory:

```java
// A file with millions of nested string concatenations
// forces the AST to be absurdly deep and wide
String x = "a"+"a"+"a"+"a"... // 5 million repetitions
```

**What happens without protection:**
JavaParser tries to parse it, allocates gigabytes, JVM runs out
of heap space, scan process crashes. In a CI environment, the
runner is killed.

**The mitigation:**
`FileWalker` checks file size before any parsing begins:

```java
static final long MAX_FILE_SIZE_BYTES = 10L * 1024 * 1024; // 10 MB

if (attrs.size() > MAX_FILE_SIZE_BYTES) {
    log.warn("Skipping oversized file ({} bytes): {}", attrs.size(), file);
    return FileVisitResult.CONTINUE; // skip, don't crash
}
```

**Why 10MB is safe:** The largest legitimate Java source files in
enterprise codebases are rarely above 500KB. 10MB is generous for
real code and blocks attack inputs.

---

## Threat 2: Reading System Files via Symlinks

**The attack:**
An attacker creates a symbolic link inside their project directory
that points to a sensitive path on the server: