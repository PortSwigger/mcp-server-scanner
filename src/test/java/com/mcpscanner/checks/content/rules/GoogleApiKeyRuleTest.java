package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GoogleApiKeyRuleTest {

    private final GoogleApiKeyRule rule = new GoogleApiKeyRule();

    @Test
    void identifiesValidGoogleApiKey() {
        String key = "AIzaSyD3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fG";

        List<Violation> violations = rule.evaluate(field("key=" + key));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo(key);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    @Test
    void suppressesWellKnownDocQuickstartKey() {
        // The Google Maps quickstart key circulated across documentation and tutorials.
        assertThat(rule.evaluate(field("key=AIzaSyClzfrOzB818x55FASHvX4JuGQciR9lv7q"))).isEmpty();
    }

    @Test
    void doesNotFireOnLowEntropyShapedPlaceholder() {
        // Shape matches AIza[35] but the body is a single repeated character — entropy is ~0,
        // so this is a documentation placeholder rather than a live key.
        assertThat(rule.evaluate(field("AIza" + "A".repeat(35)))).isEmpty();
    }

    @Test
    void ignoresShortKey() {
        assertThat(rule.evaluate(field("AIzaShort"))).isEmpty();
    }

    @Test
    void ignoresMissingPrefix() {
        assertThat(rule.evaluate(field("Bcde" + "A".repeat(35)))).isEmpty();
    }

    @Test
    void ignoresPlainText() {
        assertThat(rule.evaluate(field("nothing to see"))).isEmpty();
    }

    @Test
    void referencesPointToFirstPartyGoogleDocs() {
        assertThat(rule.metadata().references())
                .containsExactly("https://cloud.google.com/docs/authentication/api-keys");
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "maps", "description", value);
    }
}
