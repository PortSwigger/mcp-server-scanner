package com.mcpscanner.checks.issue;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IssueMetadataTest {

    @Test
    void withReferencesKeepsBackgroundRemediationAndCwes() {
        IssueMetadata base = new IssueMetadata(
                "bg", "fix", List.of(new Cwe(200, "Disclosure")), List.of("https://a"));

        IssueMetadata derived = base.withReferences(List.of("https://b", "https://c"));

        assertThat(derived.background()).isEqualTo("bg");
        assertThat(derived.remediation()).isEqualTo("fix");
        assertThat(derived.cwes()).containsExactly(new Cwe(200, "Disclosure"));
        assertThat(derived.references()).containsExactly("https://b", "https://c");
        assertThat(base.references()).containsExactly("https://a");
    }
}
