package com.mcpscanner.checks.issue;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IssueBodyBuilderTest {

    @Test
    void paragraphEscapesHtmlSpecialCharacters() {
        String html = new IssueBodyBuilder()
                .paragraph("<script>alert('x & y')</script>")
                .build();

        assertThat(html).contains("&lt;script&gt;");
        assertThat(html).contains("&amp;");
        assertThat(html).contains("&#39;");
        assertThat(html).doesNotContain("<script>");
    }

    @Test
    void paragraphWrapsTextInParagraphTag() {
        String html = new IssueBodyBuilder()
                .paragraph("hello world")
                .build();

        assertThat(html).isEqualTo("<p>hello world</p>");
    }

    @Test
    void findingsEmitUnorderedListWithListItems() {
        String html = new IssueBodyBuilder()
                .findings(List.of("first", "second"))
                .build();

        assertThat(html).contains("<ul>");
        assertThat(html).contains("<li>first</li>");
        assertThat(html).contains("<li>second</li>");
        assertThat(html).contains("</ul>");
    }

    @Test
    void findingsEscapeIndividualItems() {
        String html = new IssueBodyBuilder()
                .findings(List.of("<bad>"))
                .build();

        assertThat(html).contains("<li>&lt;bad&gt;</li>");
    }

    @Test
    void findingsEmitsNothingWhenListIsEmpty() {
        String html = new IssueBodyBuilder()
                .findings(List.of())
                .build();

        assertThat(html).isEmpty();
    }

    @Test
    void findingsEmitsNothingWhenListIsNull() {
        String html = new IssueBodyBuilder()
                .findings(null)
                .build();

        assertThat(html).isEmpty();
    }

    @Test
    void referencesEmitHeadingAndAnchorLinks() {
        String html = new IssueBodyBuilder()
                .references(List.of("https://example.com/a", "https://example.com/b"))
                .build();

        assertThat(html).contains("<p><b>References</b></p>");
        assertThat(html).contains("<a href=\"https://example.com/a\">https://example.com/a</a>");
        assertThat(html).contains("<a href=\"https://example.com/b\">https://example.com/b</a>");
    }

    @Test
    void referencesEmitsNothingWhenListIsEmpty() {
        String html = new IssueBodyBuilder()
                .references(List.of())
                .build();

        assertThat(html).isEmpty();
    }

    @Test
    void referencesEmitsNothingWhenListIsNull() {
        String html = new IssueBodyBuilder()
                .references(null)
                .build();

        assertThat(html).isEmpty();
    }

    @Test
    void vulnerabilityClassificationsEmitHeadingAndCweLinks() {
        String html = new IssueBodyBuilder()
                .vulnerabilityClassifications(List.of(
                        new Cwe(79, "Cross-site Scripting"),
                        new Cwe(829, "Untrusted Inclusion")))
                .build();

        assertThat(html).contains("<p><b>Vulnerability classifications</b></p>");
        assertThat(html).contains(
                "<a href=\"https://cwe.mitre.org/data/definitions/79.html\">"
                        + "CWE-79: Cross-site Scripting</a>");
        assertThat(html).contains(
                "<a href=\"https://cwe.mitre.org/data/definitions/829.html\">"
                        + "CWE-829: Untrusted Inclusion</a>");
    }

    @Test
    void vulnerabilityClassificationsEmitNothingWhenEmpty() {
        assertThat(new IssueBodyBuilder().vulnerabilityClassifications(List.of()).build()).isEmpty();
        assertThat(new IssueBodyBuilder().vulnerabilityClassifications(null).build()).isEmpty();
    }

    @Test
    void sectionEmitsHeadingThenBody() {
        String html = new IssueBodyBuilder()
                .section("Heading", "<p>body text</p>")
                .build();

        assertThat(html).contains("<p><b>Heading</b></p>");
        assertThat(html).contains("<p>body text</p>");
        assertThat(html.indexOf("Heading")).isLessThan(html.indexOf("body text"));
    }

    @Test
    void sectionEscapesHeadingButPreservesBodyHtml() {
        String html = new IssueBodyBuilder()
                .section("<h>", "<p>raw</p>")
                .build();

        assertThat(html).contains("<p><b>&lt;h&gt;</b></p>");
        assertThat(html).contains("<p>raw</p>");
    }

    @Test
    void chainedCallsConcatenateInOrder() {
        String html = new IssueBodyBuilder()
                .paragraph("intro")
                .findings(List.of("a", "b"))
                .paragraph("middle")
                .references(List.of("https://example.com"))
                .build();

        int introIdx = html.indexOf("intro");
        int aIdx = html.indexOf("<li>a</li>");
        int middleIdx = html.indexOf("middle");
        int refsIdx = html.indexOf("References");

        assertThat(introIdx).isGreaterThanOrEqualTo(0);
        assertThat(aIdx).isGreaterThan(introIdx);
        assertThat(middleIdx).isGreaterThan(aIdx);
        assertThat(refsIdx).isGreaterThan(middleIdx);
    }
}
