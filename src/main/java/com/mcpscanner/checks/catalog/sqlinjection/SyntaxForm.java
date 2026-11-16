package com.mcpscanner.checks.catalog.sqlinjection;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

enum SyntaxForm {

    LINE_COMMENT_AFTER_QUOTE("a closing single quote followed by a SQL line comment", "'", Shape.LINE),
    LINE_COMMENT("a SQL line comment appended to the value", "", Shape.LINE),
    LINE_COMMENT_AFTER_QUOTE_AND_PARENTHESIS(
            "a closing single quote and parenthesis followed by a SQL line comment", "')", Shape.LINE),
    LINE_COMMENT_AFTER_DOUBLE_QUOTE("a closing double quote followed by a SQL line comment", "\"", Shape.LINE),
    LINE_COMMENT_AFTER_DOUBLE_QUOTE_AND_PARENTHESIS(
            "a closing double quote and parenthesis followed by a SQL line comment", "\")", Shape.LINE),
    BACKTICK_IDENTIFIER("the value quoted as a backtick-delimited SQL identifier", "`", Shape.QUOTED_IDENTIFIER),
    INLINE_COMMENT("an inline SQL comment appended to the value", "", Shape.INLINE),
    PARENTHESISED("the value wrapped in parentheses", "", Shape.PARENTHESISED),
    DOUBLE_QUOTED_IDENTIFIER("the value quoted as a double-quoted SQL identifier", "\"", Shape.QUOTED_IDENTIFIER);

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_$]*");
    private static final Pattern IDENTIFIER_OR_NUMBER = Pattern.compile("[A-Za-z_][A-Za-z0-9_$]*|-?[0-9]+");

    private final String technique;
    private final String closer;
    private final Shape shape;

    SyntaxForm(String technique, String closer, Shape shape) {
        this.technique = technique;
        this.closer = closer;
        this.shape = shape;
    }

    static List<SyntaxForm> applicableTo(ValueSlot slot) {
        return Arrays.stream(values())
                .filter(form -> form.appliesTo(slot.segment()))
                .filter(form -> slot.isWhole() || !form.rewritesWith(ValueSlot.DELIMITERS))
                .toList();
    }

    String technique() {
        return technique;
    }

    SyntaxFamily family() {
        return switch (shape) {
            case LINE -> SyntaxFamily.LINE_COMMENT;
            case INLINE -> SyntaxFamily.INLINE_COMMENT;
            case PARENTHESISED -> SyntaxFamily.PARENTHESES;
            case QUOTED_IDENTIFIER -> "`".equals(closer) ? SyntaxFamily.BACKTICK_QUOTING : SyntaxFamily.DOUBLE_QUOTING;
        };
    }

    boolean appliesTo(String segment) {
        return switch (shape) {
            case QUOTED_IDENTIFIER -> IDENTIFIER.matcher(segment).matches();
            case PARENTHESISED -> IDENTIFIER_OR_NUMBER.matcher(segment).matches();
            default -> true;
        };
    }

    String equivalent(String segment, String token) {
        return switch (shape) {
            case INLINE -> segment + "/*" + token + "*/";
            case LINE -> segment + closer + " -- " + token;
            case QUOTED_IDENTIFIER -> closer + segment + closer;
            case PARENTHESISED -> "(" + segment + ")";
        };
    }

    String falsifier(String segment, String token) {
        return switch (shape) {
            case INLINE -> segment + "/" + token + "**/";
            case LINE -> segment + closer + " - -" + token;
            case QUOTED_IDENTIFIER -> closer + closer + segment;
            case PARENTHESISED -> "()" + segment;
        };
    }

    private boolean rewritesWith(String delimiters) {
        String rewritten = equivalent("", "") + falsifier("", "");
        return rewritten.chars().anyMatch(character -> delimiters.indexOf(character) >= 0);
    }

    private enum Shape {
        INLINE, LINE, QUOTED_IDENTIFIER, PARENTHESISED
    }
}
