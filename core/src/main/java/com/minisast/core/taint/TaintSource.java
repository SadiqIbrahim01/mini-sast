package com.minisast.core.taint;

/**
 * Categorizes where taint enters the system.
 *
 * Two categories with fundamentally different implications:
 *
 * USER_CONTROLLED: data comes directly from an external actor
 *   → attacker can set this to anything
 *   → highest risk
 *
 * DYNAMIC_CONCAT / TAINT_PROPAGATED: data was dynamically constructed
 *   → may or may not be user-controlled
 *   → still dangerous at a SQL sink — parameterize regardless
 */
public enum TaintSource {

    HTTP_PARAMETER   ("request.getParameter()",    "HTTP request query/form parameter"),
    HTTP_HEADER      ("request.getHeader()",        "HTTP request header"),
    HTTP_COOKIE      ("getCookies()",               "HTTP cookie value"),
    HTTP_BODY        ("request.getReader()",         "HTTP request body"),
    DYNAMIC_CONCAT   ("string concatenation",        "Variable built from dynamic string concat"),
    TAINT_PROPAGATED ("variable assignment",         "Tainted value propagated via assignment");

    private final String methodExample;
    private final String description;

    TaintSource(String methodExample, String description) {
        this.methodExample = methodExample;
        this.description   = description;
    }

    public String getMethodExample() { return methodExample; }
    public String getDescription()   { return description; }

    /** Returns true if this source represents confirmed external user input */
    public boolean isUserControlled() {
        return this == HTTP_PARAMETER
                || this == HTTP_HEADER
                || this == HTTP_COOKIE
                || this == HTTP_BODY;
    }
}