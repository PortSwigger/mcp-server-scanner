package com.mcpscanner.checks.catalog.sqlinjection;

record ValueSlot(String prefix, String segment, String suffix) {

    static final String DELIMITERS = "/?#";

    static ValueSlot whole(String value) {
        return new ValueSlot("", value, "");
    }

    String with(String rewritten) {
        return prefix + rewritten + suffix;
    }

    boolean isWhole() {
        return prefix.isEmpty() && suffix.isEmpty();
    }

    String described() {
        return isWhole() ? "the whole value" : "the URI segment '" + segment + "'";
    }
}
