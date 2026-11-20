package com.mcpscanner.checks.catalog.commandinjection;

import java.util.function.BinaryOperator;

enum ShellBreakout {

    COMMAND_SUBSTITUTION("$(...) command substitution", (original, command) -> original + "$(" + command + ")"),
    BACKTICK("backtick", (original, command) -> original + "`" + command + "`"),
    SEMICOLON("semicolon", (original, command) -> original + "; " + command + " #"),
    NEWLINE("newline", (original, command) -> original + "\n" + command + " #", false),
    DOUBLE_QUOTE("double-quote", (original, command) -> original + "\"; " + command + " #"),
    SINGLE_QUOTE("single-quote", (original, command) -> original + "'; " + command + " #");

    private final String described;
    private final BinaryOperator<String> wrapping;
    private final boolean singleLine;

    ShellBreakout(String described, BinaryOperator<String> wrapping) {
        this(described, wrapping, true);
    }

    ShellBreakout(String described, BinaryOperator<String> wrapping, boolean singleLine) {
        this.described = described;
        this.wrapping = wrapping;
        this.singleLine = singleLine;
    }

    String described() {
        return described;
    }

    boolean fitsOnOneLine() {
        return singleLine;
    }

    String wrap(String original, String command) {
        return wrapping.apply(original, command);
    }
}
