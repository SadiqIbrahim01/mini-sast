# Mini SAST — Rules Guide

## How Rules Work

A rule has two responsibilities and only two:

1. **Detect a pattern** in source code
2. **Return a RuleMatch** describing where and what

Nothing else. A rule does not know about CWE numbers, OWASP
categories, or how to format output. That metadata is stored
alongside the rule definition and merged in by the engine.  