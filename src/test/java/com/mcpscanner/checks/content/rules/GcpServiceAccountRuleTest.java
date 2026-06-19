package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GcpServiceAccountRuleTest {

    private final GcpServiceAccountRule rule = new GcpServiceAccountRule();

    @Test
    void identifiesServiceAccountJson() {
        String value = "{ \"type\": \"service_account\", \"private_key\": \"-----BEGIN-----\" }";

        List<Violation> violations = rule.evaluate(field(value));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void identifiesEvenWithWhitespaceAroundColons() {
        String value = "{ \"type\" : \"service_account\" , \"private_key\" : \"x\" }";

        assertThat(rule.evaluate(field(value))).hasSize(1);
    }

    @Test
    void ignoresWhenOnlyTypePresent() {
        assertThat(rule.evaluate(field("{\"type\":\"service_account\"}"))).isEmpty();
    }

    @Test
    void ignoresWhenOnlyPrivateKeyPresent() {
        assertThat(rule.evaluate(field("{\"private_key\":\"abc\"}"))).isEmpty();
    }

    @Test
    void ignoresUnrelatedJson() {
        assertThat(rule.evaluate(field("{\"name\":\"foo\"}"))).isEmpty();
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "gcp", "description", value);
    }
}
