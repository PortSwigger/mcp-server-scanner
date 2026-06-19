package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AzureConnectionStringRuleTest {

    // A realistic 64-byte Azure storage AccountKey is dense random base64 (~88 chars, high entropy).
    private static final String REALISTIC_ACCOUNT_KEY =
            "aZ3kP9mX7qW2vL8nR1tY5uH4eC6sD0fG2jK8lM4nB7vC9xQ1zA3wE5rT7yU2iO6pS8dF0gH==";

    private final AzureConnectionStringRule rule = new AzureConnectionStringRule();

    @Test
    void firesWhenHighEntropyAccountKeyPresent() {
        String secretConfig = "DefaultEndpointsProtocol=https;AccountName=secret;AccountKey=" + REALISTIC_ACCOUNT_KEY;

        List<Violation> violations = rule.evaluate(field(secretConfig));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).contains("AccountKey=");
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void doesNotFireOnRepeatedCharPlaceholderKey() {
        // Shape matches the connection string, but a repeated-char AccountKey body carries no
        // randomness — it is a documentation placeholder, not a live storage key.
        String placeholder = "DefaultEndpointsProtocol=https;AccountName=secret;AccountKey=" + "A".repeat(80) + "==";

        assertThat(rule.evaluate(field(placeholder))).isEmpty();
    }

    @Test
    void doesNotFireWithoutAccountKey() {
        String publicConfig = "DefaultEndpointsProtocol=https;AccountName=publicstorage;EndpointSuffix=core.windows.net";

        assertThat(rule.evaluate(field(publicConfig))).isEmpty();
    }

    @Test
    void firesOnHttpScheme() {
        // older Azure connection strings used http (per review §11.2)
        String secretConfig = "DefaultEndpointsProtocol=http;AccountName=legacy;AccountKey=" + REALISTIC_ACCOUNT_KEY;

        assertThat(rule.evaluate(field(secretConfig))).hasSize(1);
    }

    @Test
    void ignoresPartialPrefix() {
        assertThat(rule.evaluate(field("DefaultEndpointsProtocol=https"))).isEmpty();
    }

    @Test
    void ignoresAccountNameAlone() {
        assertThat(rule.evaluate(field("AccountName=mystorage"))).isEmpty();
    }

    @Test
    void ignoresPlainText() {
        assertThat(rule.evaluate(field("just talking about azure"))).isEmpty();
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "azure", "description", value);
    }
}
