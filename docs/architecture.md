# Mini SAST — Architecture Deep Dive

## The Central Design Decision

The `core` module has **zero framework dependencies**.
No Spring Boot. No Picocli. No web libraries. Pure Java.

This was decided in Phase 1 and never compromised. It is the reason
Phase 7 (adding the REST API) required zero changes to the detection engine.