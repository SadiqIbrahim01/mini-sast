package com.minisast.core.exception;

/** Thrown for unrecoverable scan-level failures (e.g., target path missing). */
public class ScanException extends MiniSastException {
    public ScanException(String message)                  { super(message); }
    public ScanException(String message, Throwable cause) { super(message, cause); }
}