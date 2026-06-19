package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class EmailRuleTest {

    private final EmailRule rule = new EmailRule();

    @Test
    void identifiesPlainEmail() {
        List<Violation> violations = rule.evaluate(field("Contact security@acme.io for details."));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("security@acme.io");
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void identifiesSentenceFinalEmail() {
        List<Violation> violations = rule.evaluate(field("Contact security@acme.io."));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("security@acme.io");
    }

    @Test
    void findsMultipleEmails() {
        List<Violation> violations = rule.evaluate(field("a@foo.io and b@bar.dev"));

        assertThat(violations).hasSize(2);
    }

    @Test
    void suppressesAllowListedHosts() {
        List<Violation> violations = rule.evaluate(field("user@example.com x@test.com"));

        assertThat(violations).isEmpty();
    }

    @Test
    void flagsDotExampleHosts() {
        List<Violation> violations = rule.evaluate(field("admin@internal-corp.example"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("admin@internal-corp.example");
    }

    @Test
    void suppressesReservedInternalTlds() {
        // .local (mDNS) and .internal (common enterprise internal domain) are not routable
        // external addresses, so an address on either is infrastructure noise, not exposure.
        assertThat(rule.evaluate(field("ops@corp.local"))).isEmpty();
        assertThat(rule.evaluate(field("x@svc.internal"))).isEmpty();
    }

    @Test
    void doesNotFireOnCleanString() {
        assertThat(rule.evaluate(field("no emails here, just text @"))).isEmpty();
    }

    @Test
    void suppressesExampleField() {
        InspectedField example = new InspectedField(
                SourceObjectType.TOOL, "send_email", "inputSchema.properties.to.example", "real@evil.com");

        assertThat(rule.evaluate(example)).isEmpty();
    }

    @Test
    void identifiesHyphenatedHost() {
        List<Violation> violations = rule.evaluate(field("ping a@foo-bar.io now"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("a@foo-bar.io");
    }

    @Test
    void completesOnAdversarialInputWithoutBacktracking() {
        String payload = "a@" + "a.".repeat(60000) + "!";

        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> rule.evaluate(field(payload)));
    }

    @Test
    void referencesKeepOnlyGdpr() {
        assertThat(rule.metadata().references()).containsExactly("https://gdpr-info.eu/art-4-gdpr/");
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "send_email", "description", value);
    }
}
