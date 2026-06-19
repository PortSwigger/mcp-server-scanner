package com.mcpscanner.checks.content;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ContentSuppressionTest {

    @Test
    void isAllowListedHost_acceptsExactExampleTlds() {
        assertThat(ContentSuppression.isAllowListedHost("example.com")).isTrue();
        assertThat(ContentSuppression.isAllowListedHost("example.org")).isTrue();
        assertThat(ContentSuppression.isAllowListedHost("example.net")).isTrue();
        assertThat(ContentSuppression.isAllowListedHost("test.com")).isTrue();
        assertThat(ContentSuppression.isAllowListedHost("localhost")).isTrue();
    }

    @Test
    void isAllowListedHost_rejectsHostsEndingInDotExample() {
        assertThat(ContentSuppression.isAllowListedHost("internal-corp.example")).isFalse();
        assertThat(ContentSuppression.isAllowListedHost("acme.example")).isFalse();
        assertThat(ContentSuppression.isAllowListedHost("foo.example")).isFalse();
    }

    @Test
    void allowListedHostsCaseInsensitive() {
        assertThat(ContentSuppression.isAllowListedHost("EXAMPLE.com")).isTrue();
        assertThat(ContentSuppression.isAllowListedHost("LocalHost")).isTrue();
    }

    @Test
    void realHostsNotAllowListed() {
        assertThat(ContentSuppression.isAllowListedHost("evil.com")).isFalse();
        assertThat(ContentSuppression.isAllowListedHost("my.real.host")).isFalse();
        assertThat(ContentSuppression.isAllowListedHost(null)).isFalse();
    }

    @Test
    void dummyTokensDetected() {
        // "AKIA1234EXAMPLE" — EXAMPLE at end of string is a string-boundary on the right; the left
        // side is a digit (no boundary) but the canonical AWS example key form ends in EXAMPLE so
        // we accept that the trailing boundary alone is sufficient. Today's rule requires BOTH
        // sides to be boundaries; the string-end on the right is one, and the left char being
        // alphanumeric means this no longer counts as a stand-alone marker. Use a clearer form.
        assertThat(ContentSuppression.isDummyValue("AKIA EXAMPLE")).isTrue();
        assertThat(ContentSuppression.isDummyValue("PLACEHOLDER_TOKEN")).isTrue();
        assertThat(ContentSuppression.isDummyValue("paste YOUR_API_KEY here")).isTrue();
        assertThat(ContentSuppression.isDummyValue("XXXXXXXX redacted")).isTrue();
    }

    @Test
    void realShapedValuesAreNotDummy() {
        assertThat(ContentSuppression.isDummyValue("AKIA1234567890ABCDEF")).isFalse();
        assertThat(ContentSuppression.isDummyValue(null)).isFalse();
    }

    @Test
    void dummyTokenWithoutWordBoundaryDoesNotSuppress() {
        // The marker word "EXAMPLE" appears as a substring of a legitimate-looking secret-shaped
        // value with no surrounding non-alphanumeric boundary on either side. We must NOT suppress;
        // otherwise real secrets that happen to contain the marker substring slip through.
        assertThat(ContentSuppression.isDummyValue("AKIAEXAMPLEKEYABCDEF")).isFalse();
        assertThat(ContentSuppression.isDummyValue("AKIAUNEXAMPLEDKEY1234")).isFalse();
        assertThat(ContentSuppression.isDummyValue("AKIAEXAMPLE12345678")).isFalse();
    }

    @Test
    void dummyTokenWithWordBoundarySuppresses() {
        // Underscore is a non-alphanumeric boundary on both sides.
        assertThat(ContentSuppression.isDummyValue("AKIA_EXAMPLE_KEY12345")).isTrue();
        // Marker at start of string (string-start boundary) with non-alpha on the right.
        assertThat(ContentSuppression.isDummyValue("EXAMPLE_KEY")).isTrue();
        // Marker at end of string (string-end boundary) with non-alpha on the left.
        assertThat(ContentSuppression.isDummyValue("KEY EXAMPLE")).isTrue();
    }

    @Test
    void dummyTokensMatchedCaseInsensitively() {
        assertThat(ContentSuppression.isDummyValue("paste your_api_key here")).isTrue();
        assertThat(ContentSuppression.isDummyValue("YOUR_API_KEY")).isTrue();
        assertThat(ContentSuppression.isDummyValue("example")).isTrue();
        assertThat(ContentSuppression.isDummyValue("Placeholder")).isTrue();
    }

    @Test
    void broadenedDummyTokensDetected() {
        assertThat(ContentSuppression.isDummyValue("<token>")).isTrue();
        assertThat(ContentSuppression.isDummyValue("set it to changeme now")).isTrue();
        assertThat(ContentSuppression.isDummyValue("value: xxxx")).isTrue();
        assertThat(ContentSuppression.isDummyValue("use *** instead")).isTrue();
        assertThat(ContentSuppression.isDummyValue("[REDACTED]")).isTrue();
        assertThat(ContentSuppression.isDummyValue("a placeholder string")).isTrue();
    }

    @Test
    void exampleFieldPathsDetected() {
        assertThat(ContentSuppression.isExampleField("inputSchema.properties.foo.example", null)).isTrue();
        assertThat(ContentSuppression.isExampleField("inputSchema.examples[0]", null)).isTrue();
        assertThat(ContentSuppression.isExampleField("inputSchema.properties.foo.examples[2]", null)).isTrue();
    }

    @Test
    void defaultFieldPathsAreNotTreatedAsExample() {
        // A `default` is a real configured value, not an illustrative example — keep scanning it.
        assertThat(ContentSuppression.isExampleField("inputSchema.properties.foo.default", null)).isFalse();
    }

    @Test
    void exampleObjectPrefixesDetected() {
        assertThat(ContentSuppression.isExampleField("description", "example_tool")).isTrue();
        assertThat(ContentSuppression.isExampleField("description", "test_thing")).isTrue();
        assertThat(ContentSuppression.isExampleField("description", "dummy_x")).isTrue();
        assertThat(ContentSuppression.isExampleField("description", "EXAMPLE_caps")).isTrue();
    }

    @Test
    void realFieldsNotExample() {
        assertThat(ContentSuppression.isExampleField("description", "send_email")).isFalse();
        assertThat(ContentSuppression.isExampleField(null, null)).isFalse();
    }

    @Test
    void shannonEntropyIsZeroForSingleRepeatedCharacter() {
        assertThat(ContentSuppression.shannonEntropy("AAAAAAAAAA")).isZero();
    }

    @Test
    void shannonEntropyRisesWithCharacterVariety() {
        double placeholder = ContentSuppression.shannonEntropy("AKIA" + "A".repeat(16));
        double realSecret = ContentSuppression.shannonEntropy("AKIA234567ABCDEFGHIJ");

        assertThat(placeholder).isLessThan(realSecret);
    }

    @Test
    void shannonEntropyHandlesEmptyAndNull() {
        assertThat(ContentSuppression.shannonEntropy(null)).isZero();
        assertThat(ContentSuppression.shannonEntropy("")).isZero();
    }

    @Test
    void luhnAcceptsKnownGoodNumbers() {
        assertThat(ContentSuppression.luhn("4111111111111111")).isTrue();
        assertThat(ContentSuppression.luhn("5500000000000004")).isTrue();
        assertThat(ContentSuppression.luhn("340000000000009")).isTrue();
    }

    @Test
    void luhnRejectsBadInput() {
        assertThat(ContentSuppression.luhn("1234567890123456")).isFalse();
        assertThat(ContentSuppression.luhn("")).isFalse();
        assertThat(ContentSuppression.luhn(null)).isFalse();
        assertThat(ContentSuppression.luhn("41111A1111111111")).isFalse();
    }
}
