package com.mcpscanner.checks.catalog.sqlinjection;

record Separation(SyntaxForm form, Probe equivalent, Probe falsifier) {

    boolean separates(Probe baseline) {
        return equivalent.shape().matches(baseline.shape()) && falsifier.shape().differsFrom(baseline.shape());
    }
}
