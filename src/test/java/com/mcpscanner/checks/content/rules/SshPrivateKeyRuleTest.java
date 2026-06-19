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

class SshPrivateKeyRuleTest {

    private static final String BODY_LINE = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb3xQ2mZ7vL3pN";

    private final SshPrivateKeyRule rule = new SshPrivateKeyRule();

    @Test
    void identifiesRsaKeyWithBody() {
        List<Violation> violations = rule.evaluate(
                field("-----BEGIN RSA PRIVATE KEY-----\n" + BODY_LINE + "\n-----END RSA PRIVATE KEY-----"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void doesNotFireOnHeaderOnlyMention() {
        // A tool description that merely names the PEM header format carries no key material.
        assertThat(rule.evaluate(field("provide a key in -----BEGIN RSA PRIVATE KEY----- format"))).isEmpty();
    }

    @Test
    void doesNotFireOnBareHeaderWithoutBody() {
        assertThat(rule.evaluate(field("-----BEGIN PRIVATE KEY-----"))).isEmpty();
    }

    @Test
    void identifiesEachKeyVariantWithBody() {
        String variants = "-----BEGIN RSA PRIVATE KEY-----\n" + BODY_LINE + "\n"
                + "-----BEGIN OPENSSH PRIVATE KEY-----\n" + BODY_LINE + "\n"
                + "-----BEGIN EC PRIVATE KEY-----\n" + BODY_LINE + "\n"
                + "-----BEGIN DSA PRIVATE KEY-----\n" + BODY_LINE + "\n"
                + "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + BODY_LINE;

        assertThat(rule.evaluate(field(variants))).hasSize(5);
    }

    @Test
    void ignoresUnrelatedBeginHeader() {
        assertThat(rule.evaluate(field("-----BEGIN CERTIFICATE-----\n" + BODY_LINE))).isEmpty();
    }

    @Test
    void ignoresPlainText() {
        assertThat(rule.evaluate(field("nothing here"))).isEmpty();
    }

    @Test
    void completesOnAdversarialPureNewlineRunWithoutBacktracking() {
        // A long pure-newline run terminated by a single non-newline is the shape that drove the
        // old greedy `\s*[\r\n]+` overlap into O(n^2) backtracking. A trailing whitespace run would
        // let the old pattern short-circuit, so it must be pure-newline-terminated to guard the fix.
        String payload = "-----BEGIN RSA PRIVATE KEY-----" + "\n".repeat(100000) + "X";

        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> rule.evaluate(field(payload)));
    }

    @Test
    void dropsFormatSpecReference() {
        assertThat(rule.metadata().references()).isEmpty();
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "ssh", "description", value);
    }
}
