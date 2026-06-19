package com.mcpscanner.checks.content;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class ContentRuleEngine {

    // Hard cap on the text any single rule scans. Untrusted MCP-server fields are evaluated on
    // Burp's scan threads; capping the input bounds worst-case regex cost regardless of pattern.
    private static final int MAX_FIELD_SCAN_CHARS = 64 * 1024;

    private final List<ContentRule> rules;

    public ContentRuleEngine(List<ContentRule> rules) {
        this.rules = List.copyOf(Objects.requireNonNull(rules, "rules must not be null"));
    }

    public List<ContentFinding> run(List<ContentRuleContext> contexts) {
        if (contexts == null || contexts.isEmpty()) {
            return List.of();
        }
        List<ContentFinding> findings = new ArrayList<>();
        for (ContentRuleContext context : contexts) {
            findings.addAll(runContext(context));
        }
        return findings;
    }

    private List<ContentFinding> runContext(ContentRuleContext context) {
        List<ContentFinding> findings = new ArrayList<>();
        for (ContentRule rule : rules) {
            findings.addAll(applyRule(rule, context));
        }
        return findings;
    }

    private List<ContentFinding> applyRule(ContentRule rule, ContentRuleContext context) {
        List<ContentFinding> findings = new ArrayList<>();
        for (InspectedField field : context.fields()) {
            findings.addAll(evaluateField(rule, context, capped(field)));
        }
        for (Violation violation : rule.evaluateContent(context.content(), context.host())) {
            findings.add(new ContentFinding(rule, context, violation));
        }
        return findings;
    }

    private List<ContentFinding> evaluateField(ContentRule rule, ContentRuleContext context, InspectedField field) {
        List<ContentFinding> findings = new ArrayList<>();
        try {
            for (Violation violation : rule.evaluate(field)) {
                findings.add(new ContentFinding(rule, context, violation));
            }
        } catch (RuntimeException e) {
            // A misbehaving rule (e.g. a pathological regex on hostile server text) must not abort
            // the scan or suppress findings from other rules; skip this rule for this field.
        }
        return findings;
    }

    private static InspectedField capped(InspectedField field) {
        String value = field.value();
        if (value == null || value.length() <= MAX_FIELD_SCAN_CHARS) {
            return field;
        }
        return new InspectedField(
                field.objectType(),
                field.objectName(),
                field.fieldPath(),
                value.substring(0, MAX_FIELD_SCAN_CHARS));
    }
}
