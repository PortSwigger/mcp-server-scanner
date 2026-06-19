package com.mcpscanner.checks.content.rules;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.DiscoveredContent;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import com.mcpscanner.mcp.IconDescriptor;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

class IconContentRuleTest {

    private final IconContentRule rule = new IconContentRule();

    @Test
    void flagsUnsafeScheme() {
        List<Violation> violations = evaluate(icon("file:///etc/passwd", "image/png", null),
                "server.example");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(violations.get(0).field().fieldPath()).isEqualTo("icons[0].src (unsafe scheme)");
    }

    @Test
    void fieldPathUsesHumanReadableLabelForHttpScheme() {
        List<Violation> violations = evaluate(icon("http://example.com/icon.png", "image/png", null),
                "server.example");

        assertThat(violations.get(0).field().fieldPath()).isEqualTo("icons[0].src (plaintext HTTP)");
    }

    @Test
    void flagsHttpScheme() {
        List<Violation> violations = evaluate(icon("http://example.com/icon.png", "image/png", null),
                "server.example");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    @Test
    void flagsCrossOriginHttps() {
        List<Violation> violations = evaluate(icon("https://other.example/icon.png", "image/png", null),
                "server.example");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void flagsSvgMimeType() {
        List<Violation> violations = evaluate(icon("https://server.example/i.svg", "image/svg+xml", null),
                "server.example");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void flagsOversizedDimensions() {
        List<Violation> violations = evaluate(
                icon("https://server.example/big.png", "image/png", List.of("8192x8192")),
                "server.example");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void doesNotFireOnCleanSameOriginHttpsPng() {
        List<Violation> violations = evaluate(
                icon("https://server.example/icon.png", "image/png", List.of("128x128")),
                "server.example");

        assertThat(violations).isEmpty();
    }

    @Test
    void flagsCrossOriginSvgServerLevelIcon() {
        // homeassistant-ai/ha-mcp v7.6.0: server-level cross-origin SVG icon.
        List<Violation> violations = evaluateServerIcons(
                List.of(icon(
                        "https://raw.githubusercontent.com/home-assistant/brands/master/core_integrations/mcp/icon.svg",
                        "image/svg+xml", null)),
                "ha-mcp.example");

        assertThat(violations).hasSize(2);
        assertThat(violations).extracting(v -> v.severity()).containsExactlyInAnyOrder(
                AuditIssueSeverity.LOW, AuditIssueSeverity.INFORMATION);
        assertThat(violations).allSatisfy(v ->
                assertThat(v.field().objectType()).isEqualTo(SourceObjectType.SERVER_INFO));
    }

    @Test
    void flagsDataSvgServerLevelIcon() {
        // freelawproject/courtlistener: server-level data:image/svg+xml icon.
        List<Violation> violations = evaluateServerIcons(
                List.of(icon("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=", "image/svg+xml", null)),
                "courtlistener.example");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(violations.get(0).field().objectType()).isEqualTo(SourceObjectType.SERVER_INFO);
    }

    @Test
    void courtListenerDataPngServerIconStaysSilent() {
        // The companion data:image/png;base64 icon is a safe raster — no finding.
        List<Violation> violations = evaluateServerIcons(
                List.of(icon("data:image/png;base64,iVBORw0KGgo=", "image/png", null)),
                "courtlistener.example");

        assertThat(violations).isEmpty();
    }

    @Test
    void flagsHttpServerLevelIcon() {
        List<Violation> violations = evaluateServerIcons(
                List.of(icon("http://server.example/logo.png", "image/png", null)),
                "server.example");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(violations.get(0).field().objectType()).isEqualTo(SourceObjectType.SERVER_INFO);
    }

    @Test
    void safeSameOriginRasterServerIconStaysSilent() {
        List<Violation> violations = evaluateServerIcons(
                List.of(icon("https://server.example/logo.png", "image/png", List.of("128x128"))),
                "server.example");

        assertThat(violations).isEmpty();
    }

    @Test
    void serverWithNoIconsProducesNoFindingAndNoNpe() {
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(), List.of(), List.of(), List.of());

        assertThat(rule.evaluateContent(content, host("server.example"))).isEmpty();
    }

    @Test
    void flagsSvgBySrcExtensionWhenMimeTypeAbsent() {
        // EverythingServer-style: cross-origin .svg with no mimeType.
        List<Violation> violations = evaluateServerIcons(
                List.of(icon("https://cdn.example/brand/logo.SVG", null, null)),
                "server.example");

        // Cross-origin (LOW) + SVG-by-extension (INFORMATION).
        assertThat(violations).hasSize(2);
        assertThat(violations).extracting(v -> v.severity()).containsExactlyInAnyOrder(
                AuditIssueSeverity.LOW, AuditIssueSeverity.INFORMATION);
    }

    @Test
    void sameOriginSvgBySrcExtensionStillFlagsSvgOnly() {
        List<Violation> violations = evaluateServerIcons(
                List.of(icon("https://server.example/logo.svg", null, null)),
                "server.example");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    private List<Violation> evaluate(IconDescriptor icon, String serverHost) {
        McpToolDefinition tool = new McpToolDefinition("logo", "desc", null, List.of(icon));
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());
        return rule.evaluateContent(content, host(serverHost));
    }

    private List<Violation> evaluateServerIcons(List<IconDescriptor> icons, String serverHost) {
        ServerMetadata metadata = new ServerMetadata(java.util.Map.of(), "", java.util.Map.of(), icons);
        DiscoveredContent content = new DiscoveredContent(
                metadata, List.of(), List.of(), List.of(), List.of());
        return rule.evaluateContent(content, host(serverHost));
    }

    private static IconDescriptor icon(String src, String mimeType, List<String> sizes) {
        return new IconDescriptor(src, mimeType, sizes);
    }

    private static HttpService host(String host) {
        HttpService service = mock(HttpService.class);
        lenient().when(service.host()).thenReturn(host);
        return service;
    }
}
