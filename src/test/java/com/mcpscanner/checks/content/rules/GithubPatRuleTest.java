package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GithubPatRuleTest {

    private final GithubPatRule rule = new GithubPatRule();

    @Test
    void identifiesAllClassicPrefixes() {
        String body = "ghp_aB3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fG2H "
                + "gho_kM7pQ1rS9tU3vW5xY2zA4bC6dE8fG0hJ1iK3 "
                + "ghu_nO5pR2qT8uV4wX6yZ1aB3cD7eF9gH0jK2lM4 "
                + "ghs_pQ3rS7tU1vW9xY5zA2bC4dE6fG8hJ0kL1mN3 "
                + "ghr_qR9sT4uV2wX6yZ8aB1cD3eF5gH7jK0lM2nO4";

        List<Violation> violations = rule.evaluate(field(body));

        assertThat(violations).hasSize(5);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void identifiesFineGrainedToken() {
        String token = "github_pat_" + ("aB3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fG".repeat(3)).substring(0, 82);

        List<Violation> violations = rule.evaluate(field("token=" + token));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo(token);
    }

    @Test
    void doesNotFireOnLowEntropyShapedPlaceholder() {
        // ghp_ + 36 repeated characters: matches the shape but carries no real randomness.
        assertThat(rule.evaluate(field("ghp_" + "A".repeat(36)))).isEmpty();
    }

    @Test
    void ignoresShortPrefix() {
        assertThat(rule.evaluate(field("ghp_short"))).isEmpty();
    }

    @Test
    void ignoresUnknownPrefix() {
        assertThat(rule.evaluate(field("ghx_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))).isEmpty();
    }

    @Test
    void ignoresPlainText() {
        assertThat(rule.evaluate(field("nothing to see here"))).isEmpty();
    }

    @Test
    void suppressesDummyValueWhenMarkerIsWordBounded() {
        // YOUR_TOKEN_HERE flanked by underscores (non-alphanumeric boundaries) on both sides.
        // High-entropy tail proves the suppression comes from the dummy marker, not the entropy floor.
        String token = "github_pat_YOUR_TOKEN_HERE_"
                + ("aB3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fG".repeat(2)).substring(0, 66);

        assertThat(rule.evaluate(field(token))).isEmpty();
    }

    @Test
    void doesNotSuppressWhenMarkerIsEmbeddedWithoutBoundaries() {
        // Trailing alphanumerics extend the marker substring: no word boundary on the right.
        // Real-looking high-entropy secret-shaped value must be flagged.
        String token = "github_pat_YOUR_TOKEN_HERE"
                + ("aB3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fG".repeat(2)).substring(0, 67);

        List<Violation> violations = rule.evaluate(field(token));
        assertThat(violations).hasSize(1);
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "github", "description", value);
    }
}
