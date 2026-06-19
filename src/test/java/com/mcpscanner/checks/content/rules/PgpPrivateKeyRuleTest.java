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

class PgpPrivateKeyRuleTest {

    private static final String BODY_LINE = "lQVYBGV3xQ2mZ7vL3pNwT1yU6iO4eC0sD5fG2hJ4kL8mN3qZ7vL9pT1yU6iO4eC0";

    private final PgpPrivateKeyRule rule = new PgpPrivateKeyRule();

    @Test
    void identifiesPgpPrivateKeyWithBody() {
        List<Violation> violations = rule.evaluate(
                field("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + BODY_LINE + "\n-----END PGP PRIVATE KEY BLOCK-----"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void doesNotFireOnHeaderOnlyMention() {
        // Naming the armor header in a description carries no actual key material.
        assertThat(rule.evaluate(field("paste a -----BEGIN PGP PRIVATE KEY BLOCK----- here"))).isEmpty();
    }

    @Test
    void ignoresPgpPublicKeyHeader() {
        assertThat(rule.evaluate(field("-----BEGIN PGP PUBLIC KEY BLOCK-----\n" + BODY_LINE))).isEmpty();
    }

    @Test
    void ignoresUnrelatedBegin() {
        assertThat(rule.evaluate(field("-----BEGIN CERTIFICATE-----\n" + BODY_LINE))).isEmpty();
    }

    @Test
    void ignoresPlainText() {
        assertThat(rule.evaluate(field("pgp talked about"))).isEmpty();
    }

    @Test
    void completesOnAdversarialColonLinesWithoutBacktracking() {
        String payload = "-----BEGIN PGP PRIVATE KEY BLOCK-----" + " :\n".repeat(20000);

        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> rule.evaluate(field(payload)));
    }

    @Test
    void completesOnAdversarialPureNewlineRunWithoutBacktracking() {
        // A long pure-newline run terminated by a single non-newline is the shape that drove the
        // old greedy `\s*[\r\n]+` overlap into O(n^2) backtracking. A trailing whitespace run would
        // let the old pattern short-circuit, so it must be pure-newline-terminated to guard the fix.
        String payload = "-----BEGIN PGP PRIVATE KEY BLOCK-----" + "\n".repeat(100000) + "X";

        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> rule.evaluate(field(payload)));
    }

    @Test
    void dropsFormatSpecReference() {
        assertThat(rule.metadata().references()).isEmpty();
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "pgp", "description", value);
    }
}
