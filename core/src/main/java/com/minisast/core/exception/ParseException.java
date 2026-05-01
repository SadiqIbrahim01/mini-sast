package com.minisast.core.exception;

/** Thrown when a source file cannot be parsed. Recoverable — scan continues. */
public class ParseException extends MiniSastException {

    private final String filePath;

    public ParseException(String filePath, String message, Throwable cause) {
        super("Parse failure in [%s]: %s".formatted(filePath, message), cause);
        this.filePath = filePath;
    }

    public ParseException(String filePath, String message) {
        this(filePath, message, null);
    }

    public String getFilePath() { return filePath; }
}