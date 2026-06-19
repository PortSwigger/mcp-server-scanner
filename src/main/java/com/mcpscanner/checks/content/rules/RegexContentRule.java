package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.ContentSuppression;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.Violation;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

abstract class RegexContentRule implements ContentRule {

    private final List<Pattern> patterns;

    RegexContentRule(Pattern... patterns) {
        this.patterns = List.of(patterns);
    }

    @Override
    public List<Violation> evaluate(InspectedField field) {
        if (field == null || field.value() == null || field.value().isEmpty()) {
            return List.of();
        }
        if (ContentSuppression.isExampleField(field.fieldPath(), field.objectName())) {
            return List.of();
        }
        List<Violation> violations = new ArrayList<>();
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(field.value());
            while (matcher.find()) {
                String match = matcher.group();
                if ((appliesDummyTokenSuppression() && ContentSuppression.isDummyValue(match))
                        || isSuppressedMatch(match)) {
                    continue;
                }
                violations.add(new Violation(this, field, match, severityFor(match)));
            }
        }
        return violations;
    }

    protected boolean isSuppressedMatch(String match) {
        return false;
    }

    // Per-match severity hook. Defaults to the rule severity; rules where a subset of matches
    // (e.g. sandbox/test credentials) warrant a different severity override this.
    protected AuditIssueSeverity severityFor(String match) {
        return severity();
    }

    protected boolean appliesDummyTokenSuppression() {
        return true;
    }
}
