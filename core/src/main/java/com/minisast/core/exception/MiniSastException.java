package com.minisast.core.exception;

/** Base unchecked exception for Mini SAST. All domain exceptions extend this. */
public class MiniSastException extends RuntimeException {
    public MiniSastException(String message)                  { super(message); }
    public MiniSastException(String message, Throwable cause) { super(message, cause); }
}