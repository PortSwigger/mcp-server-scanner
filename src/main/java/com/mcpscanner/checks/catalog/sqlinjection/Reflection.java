package com.mcpscanner.checks.catalog.sqlinjection;

record Reflection(String sent, String original) {

    static final Reflection NONE = new Reflection("", "");

    String undo(String text) {
        return sent.isEmpty() || sent.equals(original) ? text : text.replace(sent, original);
    }
}
