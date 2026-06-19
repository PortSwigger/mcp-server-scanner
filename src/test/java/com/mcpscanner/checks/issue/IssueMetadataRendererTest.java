package com.mcpscanner.checks.issue;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IssueMetadataRendererTest {

    @Test
    void backgroundRendersProseThenCwesThenReferences() {
        IssueMetadata metadata = new IssueMetadata(
                "Operator-facing prose.",
                "remediation",
                List.of(new Cwe(918, "SSRF")),
                List.of("https://example.test/ref"));

        String html = IssueMetadataRenderer.background(metadata);

        assertThat(html).contains("<p>Operator-facing prose.</p>");
        assertThat(html).contains("CWE-918: SSRF");
        assertThat(html).contains("https://example.test/ref");
        assertThat(html.indexOf("prose")).isLessThan(html.indexOf("CWE-918"));
        assertThat(html.indexOf("CWE-918")).isLessThan(html.indexOf("References"));
    }

    @Test
    void overloadMatchesMetadataRendering() {
        IssueMetadata metadata = new IssueMetadata(
                "prose", "fix", List.of(new Cwe(22, "Path Traversal")), List.of("https://r"));

        assertThat(IssueMetadataRenderer.background("prose", metadata.cwes(), metadata.references()))
                .isEqualTo(IssueMetadataRenderer.background(metadata));
    }
}
