package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SlackTokenRuleTest {

    private final SlackTokenRule rule = new SlackTokenRule();

    @Test
    void identifiesBotToken() {
        String token = "xoxb-1234567890-1234567890-abcdefABCDEF0123456789ab";
        List<Violation> violations = rule.evaluate(field("token=" + token));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo(token);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void identifiesUserToken() {
        String token = "xoxp-1234567890-1234567890-abcdefABCDEF0123456789ab";
        assertThat(rule.evaluate(field(token))).hasSize(1);
    }

    @Test
    void identifiesAppLevelXappToken() {
        // Real Slack app-level tokens carry a 64-char hex authenticator at the tail.
        String token = "xapp-1-A12345678-1234567890123-"
                + "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assertThat(rule.evaluate(field(token))).hasSize(1);
    }

    @Test
    void identifiesXoxeRotationToken() {
        String token = "xoxe-12345-12345abcdefABCDEFabcdef";
        assertThat(rule.evaluate(field(token))).hasSize(1);
    }

    @Test
    void doesNotFireOnLowEntropyShapedPlaceholder() {
        // Well-formed xoxb shape but the authenticator segment is a single repeated character.
        assertThat(rule.evaluate(field("xoxb-1234567890-1234567890-" + "A".repeat(30)))).isEmpty();
    }

    @Test
    void doesNotFireOnTooShortXoxbString() {
        assertThat(rule.evaluate(field("xoxb-aaaaaaaaaaa"))).isEmpty();
    }

    @Test
    void ignoresPlainXox() {
        assertThat(rule.evaluate(field("xox is not a token"))).isEmpty();
    }

    @Test
    void ignoresShortToken() {
        assertThat(rule.evaluate(field("xoxb-short"))).isEmpty();
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "slack", "description", value);
    }
}
