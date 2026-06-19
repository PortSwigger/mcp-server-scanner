package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.ContentSuppression;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.Violation;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;

public final class GcpServiceAccountRule implements ContentRule {

    private static final String TYPE_MARKER = "\"type\":\"service_account\"";
    private static final String PRIVATE_KEY_MARKER = "\"private_key\":";

    @Override
    public String id() {
        return "discovery-content-scanner.gcp-service-account";
    }

    @Override
    public String displayName() {
        return "GCP Service Account JSON";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.HIGH;
    }

    @Override
    public List<Violation> evaluate(InspectedField field) {
        if (field == null || field.value() == null) {
            return List.of();
        }
        if (ContentSuppression.isExampleField(field.fieldPath(), field.objectName())) {
            return List.of();
        }
        String value = field.value().replaceAll("\\s+", "");
        if (value.contains(TYPE_MARKER) && value.contains(PRIVATE_KEY_MARKER)) {
            return List.of(new Violation(this, field, TYPE_MARKER + " + " + PRIVATE_KEY_MARKER));
        }
        return List.of();
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.CREDENTIAL.withReferences(List.of(
                "https://cloud.google.com/iam/docs/keys-create-delete"));
    }
}
