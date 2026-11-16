package com.mcpscanner.checks.catalog.ssrffilterbypass;

record FetchField(String name, String operation) {

    String subject() {
        return name + " in " + operation;
    }
}
