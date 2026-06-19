package com.mcpscanner.checks.content.rules;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtRuleTest {

    private final JwtRule rule = new JwtRule();

    // A realistic HS256 JWT whose payload + signature carry real randomness (high entropy).
    private static final String REALISTIC_JWT =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    + ".eyJzdWIiOiJhZjkzbTJ4UTd6Iiwicj3vbGUiOiJhZG1pbiIsImtpZCI6Ik5xN3BWMiJ9"
                    + ".kR9xQ2mZ7vL3pN8wT1yU6iO4eC0sD5fG2hJ4kL8mN3q";

    @Test
    void identifiesRealisticHighEntropyJwt() {
        List<Violation> violations = rule.evaluate(field("token=" + REALISTIC_JWT));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo(REALISTIC_JWT);
    }

    @Test
    void realisticJwtIsInformationalSeverity() {
        List<Violation> violations = rule.evaluate(field("token=" + REALISTIC_JWT));

        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void jwtRuleIsTentative() {
        assertThat(rule.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void identifiesMultipleJwts() {
        String jwt2 = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ilo5cTJ4In0"
                + ".eyJpc3MiOiJhYzkzbTJ4UTd6IiwiYXVkIjoicThuVjVwTDIifQ"
                + ".bN3qZ7vL9pT1yU6iO4eC0sD5fG2hJ8kR4mW7xQ2zA";

        assertThat(rule.evaluate(field(REALISTIC_JWT + " " + jwt2))).hasSize(2);
    }

    @Test
    void ignoresIncompleteJwt() {
        assertThat(rule.evaluate(field("eyJabc.eyJdef"))).isEmpty();
    }

    @Test
    void ignoresShortSegments() {
        assertThat(rule.evaluate(field("eyJa.eyJb.c"))).isEmpty();
    }

    @Test
    void suppressesJwtIoCanonicalExample() {
        String example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assertThat(rule.evaluate(field(example))).isEmpty();
    }

    @Test
    void suppressesRfc7519ExampleToken() {
        String example = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assertThat(rule.evaluate(field(example))).isEmpty();
    }

    @Test
    void doesNotFireOnLowEntropyAlgNoneSampleToken() {
        // The canonical alg:none sample token (empty signature, tiny low-entropy payload) is a
        // documentation artefact, not a live credential — entropy gating must drop it.
        String jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.";

        assertThat(rule.evaluate(field("token=" + jwt))).isEmpty();
    }

    @Test
    void referencesKeepOnlyActionableJwtSpec() {
        assertThat(rule.metadata().references())
                .containsExactly("https://www.rfc-editor.org/rfc/rfc7519");
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "auth", "description", value);
    }
}
