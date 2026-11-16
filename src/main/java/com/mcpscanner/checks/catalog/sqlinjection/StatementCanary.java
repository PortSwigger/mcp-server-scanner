package com.mcpscanner.checks.catalog.sqlinjection;

record StatementCanary(long left, long right) {

    String statement() {
        return "SELECT " + left + "*" + right;
    }

    String brokenStatement() {
        return "SELECT " + left + " " + right + "*";
    }

    String product() {
        return Long.toString(left * right);
    }
}
