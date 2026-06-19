package com.mcpscanner.checks.content.rules;

import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AwsAccessKeyRuleTest {

    private final AwsAccessKeyRule rule = new AwsAccessKeyRule();

    @Test
    void identifiesAkiaKey() {
        List<Violation> violations = rule.evaluate(field("key=AKIA234567ABCDEFGHIJ in config"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("AKIA234567ABCDEFGHIJ");
    }

    @Test
    void identifiesAsiaTemporaryKey() {
        List<Violation> violations = rule.evaluate(field("ASIA234567ABCDEFGHIJ"));

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("ASIA234567ABCDEFGHIJ");
    }

    @Test
    void doesNotFlagNonAccessKeyUniqueIds() {
        // AIDA/AROA/AGPA/ANPA/ABIA/APKA are user/role/group/policy unique IDs per the AWS
        // unique-ID reference — useful for recon but not credentials, so they don't belong
        // in an "access keys" detector.
        String body = "AIDAZZZZZZZZZZZZZZZZ AROAZZZZZZZZZZZZZZZZ AGPA234567ABCDEFGHIJ "
                + "ANPA234567ABCDEFGHIJ ABIA234567ABCDEFGHIJ APKA234567ABCDEFGHIJ";

        assertThat(rule.evaluate(field(body))).isEmpty();
    }

    @Test
    void suppressesAwsCanonicalExample() {
        assertThat(rule.evaluate(field("AKIAIOSFODNN7EXAMPLE"))).isEmpty();
    }

    @Test
    void doesNotSuppressWhenDummyMarkerIsEmbeddedWithoutWordBoundaries() {
        // EXAMPLE appears as an interior substring without surrounding non-alphanumeric boundaries.
        // Previously this was suppressed as a "dummy" value; the new rule treats it as a real
        // key-shaped match because attackers can hide secrets by embedding marker substrings.
        List<Violation> violations = rule.evaluate(field("AKIAEXAMPLEKEYABCDEF"));
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("AKIAEXAMPLEKEYABCDEF");
    }

    @Test
    void doesNotSuppressRealKeyWhenWordExampleAppearsElsewhereInField() {
        // The real key AKIA234567ABCDEFGHIJ should not be suppressed even though
        // EXAMPLE appears elsewhere in the surrounding field value.
        List<Violation> violations = rule.evaluate(field(
                "Use the EXAMPLE key in dev: AKIA234567ABCDEFGHIJ"));
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("AKIA234567ABCDEFGHIJ");
    }

    @Test
    void doesNotFireOnLowEntropyShapedPlaceholder() {
        // AKIA + 16 repeated Base32 characters: matches the shape but carries no real randomness.
        assertThat(rule.evaluate(field("AKIA" + "A".repeat(16)))).isEmpty();
    }

    @Test
    void firesOnGenuineKeyInLowerEntropyTail() {
        // A real random AWS key whose body lands in the lower tail of the distribution
        // (entropy ~2.87 bits/char). The default 3.0 floor would silently drop it; AWS's
        // lowered floor keeps it flagged while still rejecting the repeated-character placeholder.
        List<Violation> violations = rule.evaluate(field("AKIAVZZ5ZAIKKTIPBIZI"));
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).matchedText()).isEqualTo("AKIAVZZ5ZAIKKTIPBIZI");
    }

    @Test
    void doesNotFireOnShortString() {
        assertThat(rule.evaluate(field("AKIA12345"))).isEmpty();
    }

    @Test
    void rejectsKeysWithBase32IllegalDigits() {
        // 0/1/8/9 do not appear in real AWS keys (Base32 charset is [A-Z2-7])
        assertThat(rule.evaluate(field("key=AKIA0111000089ABCDEF"))).isEmpty();
    }

    @Test
    void referencesAreAuthoritativeAndActionable() {
        assertThat(rule.metadata().references())
                .containsExactly("https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html");
    }

    private static InspectedField field(String value) {
        return new InspectedField(SourceObjectType.TOOL, "aws_helper", "description", value);
    }
}
