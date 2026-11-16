package com.mcpscanner.checks.catalog.sqlinjection;

enum SyntaxFamily {

    LINE_COMMENT(true),
    BACKTICK_QUOTING(true),
    INLINE_COMMENT(false),
    PARENTHESES(false),
    DOUBLE_QUOTING(false);

    private final boolean sqlSpecific;

    SyntaxFamily(boolean sqlSpecific) {
        this.sqlSpecific = sqlSpecific;
    }

    boolean sqlSpecific() {
        return sqlSpecific;
    }
}
