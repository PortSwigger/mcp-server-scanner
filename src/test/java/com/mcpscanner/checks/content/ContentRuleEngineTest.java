package com.mcpscanner.checks.content;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.content.rules.AwsAccessKeyRule;
import com.mcpscanner.checks.content.rules.EmailRule;
import com.mcpscanner.checks.content.rules.RuleMetadata;
import com.mcpscanner.checks.content.rules.SshPrivateKeyRule;
import com.mcpscanner.checks.issue.IssueMetadata;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ContentRuleEngineTest {

    private HttpService host;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        host = mock(HttpService.class);
        lenient().when(host.host()).thenReturn("mcp.example.test");
        lenient().when(host.port()).thenReturn(443);
        lenient().when(host.secure()).thenReturn(true);
    }

    @Test
    void engineRunsAllRegisteredRulesAgainstPayload() {
        ContentRuleEngine engine = new ContentRuleEngine(
                List.of(new AwsAccessKeyRule(), new SshPrivateKeyRule()));
        McpToolDefinition leaky = new McpToolDefinition(
                "leak",
                "key=AKIA234567ABCDEFGHIJ and -----BEGIN RSA PRIVATE KEY-----\n"
                        + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb3xQ2mZ7vL3pN",
                null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(leaky), List.of(), List.of(), List.of());

        List<ContentFinding> findings = engine.run(
                List.of(ContentRuleContext.forDiscoveryBundle("https://mcp.example.test", content, host)));

        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(f -> f.rule().id())
                .containsExactlyInAnyOrder(
                        new AwsAccessKeyRule().id(),
                        new SshPrivateKeyRule().id());
    }

    @Test
    void engineReturnsEmptyWhenNoRulesMatch() {
        ContentRuleEngine engine = new ContentRuleEngine(
                List.of(new AwsAccessKeyRule(), new EmailRule()));
        McpToolDefinition clean = new McpToolDefinition("clean", "no secrets here", null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(clean), List.of(), List.of(), List.of());

        List<ContentFinding> findings = engine.run(
                List.of(ContentRuleContext.forDiscoveryBundle("https://mcp.example.test", content, host)));

        assertThat(findings).isEmpty();
    }

    @Test
    void engineHandlesEmptyContextList() {
        ContentRuleEngine engine = new ContentRuleEngine(List.of(new AwsAccessKeyRule()));

        assertThat(engine.run(List.of())).isEmpty();
        assertThat(engine.run(null)).isEmpty();
    }

    @Test
    void flagsSecretNearStartOfOversizedFieldAfterTruncation() {
        ContentRuleEngine engine = new ContentRuleEngine(List.of(new AwsAccessKeyRule()));
        String oversized = "AKIA234567ABCDEFGHIJ" + "x".repeat(200_000);
        McpToolDefinition leaky = new McpToolDefinition("leak", oversized, null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(leaky), List.of(), List.of(), List.of());

        List<ContentFinding> findings = engine.run(
                List.of(ContentRuleContext.forDiscoveryBundle("https://mcp.example.test", content, host)));

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).matchedText()).isEqualTo("AKIA234567ABCDEFGHIJ");
    }

    @Test
    void throwingRuleDoesNotSuppressFindingsFromOtherRules() {
        ContentRule throwing = new ThrowingRule();
        ContentRuleEngine engine = new ContentRuleEngine(List.of(throwing, new AwsAccessKeyRule()));
        McpToolDefinition leaky = new McpToolDefinition("leak", "AKIA234567ABCDEFGHIJ", null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(leaky), List.of(), List.of(), List.of());

        List<ContentFinding> findings = engine.run(
                List.of(ContentRuleContext.forDiscoveryBundle("https://mcp.example.test", content, host)));

        assertThat(findings).extracting(f -> f.rule().id())
                .containsExactly(new AwsAccessKeyRule().id());
    }

    @Test
    void findingCarriesViolationSeverity() {
        ContentRuleEngine engine = new ContentRuleEngine(List.of(new AwsAccessKeyRule()));
        McpToolDefinition leaky = new McpToolDefinition(
                "leak", "AKIA234567ABCDEFGHIJ", null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(leaky), List.of(), List.of(), List.of());

        List<ContentFinding> findings = engine.run(
                List.of(ContentRuleContext.forDiscoveryBundle("https://mcp.example.test", content, host)));

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(findings.get(0).matchedText()).isEqualTo("AKIA234567ABCDEFGHIJ");
    }

    private static final class ThrowingRule implements ContentRule {
        @Override
        public String id() {
            return "test.throwing";
        }

        @Override
        public String displayName() {
            return "Throwing Rule";
        }

        @Override
        public AuditIssueSeverity severity() {
            return AuditIssueSeverity.INFORMATION;
        }

        @Override
        public List<Violation> evaluate(InspectedField field) {
            throw new IllegalStateException("boom");
        }

        @Override
        public IssueMetadata metadata() {
            return RuleMetadata.CREDENTIAL;
        }
    }
}
