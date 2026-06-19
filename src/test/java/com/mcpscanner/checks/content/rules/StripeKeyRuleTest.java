package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class StripeKeyRuleTest {

    private static final String BODY_24 = "aB3xZ9qWmK2vL7nP1rT5yU8i";
    private static final String BODY_32 = "aB3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0";

    private final StripeKeyRule rule = new StripeKeyRule();

    @Test
    void identifiesSecretLiveKey() {
        String key = "sk_live_" + BODY_24;

        List<Violation> violations = rule.evaluate(field("token=" + key));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo(key);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void identifiesSecretAndRestrictedKeyVariants() {
        String body = "sk_live_" + BODY_24
                + " sk_test_" + BODY_32.substring(0, 24)
                + " rk_live_" + BODY_24.toUpperCase()
                + " rk_test_" + "qW3eR5tY7uI9oP1aS2dF4gH6";

        assertThat(rule.evaluate(field(body))).hasSize(4);
    }

    @Test
    void doesNotFlagPublishableLiveKey() {
        String key = "pk_live_" + BODY_24;

        assertThat(rule.evaluate(field("token=" + key))).isEmpty();
    }

    @Test
    void doesNotFlagPublishableTestKey() {
        String key = "pk_test_" + BODY_24;

        assertThat(rule.evaluate(field("token=" + key))).isEmpty();
    }

    @Test
    void testSecretKeyFiresAtLowSeverity() {
        // sk_test_ keys are sandbox credentials: still worth surfacing, but not a HIGH live-secret
        // disclosure. They are reported at LOW so they do not crowd out live-key findings.
        String key = "sk_test_" + BODY_24;

        List<Violation> violations = rule.evaluate(field(key));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo(key);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void testRestrictedKeyFiresAtLowSeverity() {
        String key = "rk_test_" + BODY_24;

        List<Violation> violations = rule.evaluate(field(key));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void liveRestrictedKeyStaysHigh() {
        List<Violation> violations = rule.evaluate(field("rk_live_" + BODY_24));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void doesNotFireOnLowEntropyShapedPlaceholder() {
        // sk_live_ + 24 repeated characters: matches the shape but carries no real randomness.
        assertThat(rule.evaluate(field("sk_live_" + "A".repeat(24)))).isEmpty();
    }

    @Test
    void ignoresShortKey() {
        assertThat(rule.evaluate(field("sk_live_short"))).isEmpty();
    }

    @Test
    void ignoresPlainText() {
        assertThat(rule.evaluate(field("no keys here"))).isEmpty();
    }

    @Test
    void doesNotSuppressWhenMarkerIsEmbeddedWithoutBoundaries() {
        // PLACEHOLDER followed by trailing alphanumerics has no right boundary; flag as real key
        // rather than treating the embedded marker as a stand-alone dummy token. A high-entropy
        // tail keeps the entropy floor from masking what this test is actually checking.
        List<Violation> violations = rule.evaluate(field("sk_live_PLACEHOLDER" + BODY_24));
        assertThat(violations).hasSize(1);
    }

    @Test
    void identifiesRestrictedKey() {
        assertThat(rule.evaluate(field("rk_live_" + BODY_24))).hasSize(1);
    }

    @Test
    void identifiesRestrictedTestKey() {
        assertThat(rule.evaluate(field("rk_test_" + BODY_24))).hasSize(1);
    }

    @Test
    void identifiesWebhookSigningSecret() {
        assertThat(rule.evaluate(field("whsec_" + BODY_32))).hasSize(1);
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "stripe", "description", value);
    }
}
