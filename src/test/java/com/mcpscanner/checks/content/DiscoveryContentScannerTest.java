package com.mcpscanner.checks.content;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;
import com.mcpscanner.checks.content.rules.AwsAccessKeyRule;
import com.mcpscanner.checks.content.rules.EmailRule;
import com.mcpscanner.checks.content.rules.IconContentRule;
import com.mcpscanner.checks.content.rules.JwtRule;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.mcp.IconDescriptor;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DiscoveryContentScannerTest {

    private static final String JWT_FIXTURE =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signaturePartIsLong";
    private static final String DISCOVERY_QUALIFIER =
            ContentFindingIssueBuilder.DISCOVERY_SOURCE.nameQualifier();

    private static String discoveryName(ContentRule rule) {
        return rule.displayName() + DISCOVERY_QUALIFIER;
    }

    private MontoyaApi api;
    private SiteMap siteMap;
    private ScanCheckSettings settings;
    private HttpService host;
    private List<ContentRule> rules;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        api = mock(MontoyaApi.class);
        siteMap = mock(SiteMap.class);
        when(api.siteMap()).thenReturn(siteMap);
        settings = mock(ScanCheckSettings.class);
        lenient().when(settings.isEnabled(any(String.class), any(Boolean.class))).thenReturn(true);
        host = mock(HttpService.class);
        lenient().when(host.host()).thenReturn("mcp.example.test");
        lenient().when(host.port()).thenReturn(443);
        lenient().when(host.secure()).thenReturn(true);
        rules = List.of(new EmailRule(), new JwtRule(), new AwsAccessKeyRule());
    }

    @Test
    void emitsOneIssuePerRuleThatFires() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        List<AuditIssue> issues = capturedIssues();
        assertThat(issues).hasSize(3);
        assertThat(issues).extracting(AuditIssue::name).containsExactlyInAnyOrder(
                discoveryName(new EmailRule()),
                discoveryName(new JwtRule()),
                discoveryName(new AwsAccessKeyRule()));
    }

    @Test
    void issueSeverityMatchesRule() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        List<AuditIssue> issues = capturedIssues();
        AuditIssue emailIssue = issueNamed(issues, discoveryName(new EmailRule()));
        AuditIssue jwtIssue = issueNamed(issues, discoveryName(new JwtRule()));
        AuditIssue awsIssue = issueNamed(issues, discoveryName(new AwsAccessKeyRule()));

        assertThat(emailIssue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(jwtIssue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(awsIssue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void issueConfidenceMatchesRuleConfidence() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        List<AuditIssue> issues = capturedIssues();
        AuditIssue emailIssue = issueNamed(issues, discoveryName(new EmailRule()));
        AuditIssue awsIssue = issueNamed(issues, discoveryName(new AwsAccessKeyRule()));

        assertThat(emailIssue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(awsIssue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void detailContainsMatchedValueAndSourceObjectName() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        AuditIssue emailIssue = issueNamed(capturedIssues(), discoveryName(new EmailRule()));
        assertThat(emailIssue.detail())
                .contains("alice@acme.io")
                .contains("send_email");
    }

    @Test
    void detailUsesSingularWhenOneFindingAndNoDoubleContentWording() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        AuditIssue awsIssue = issueNamed(capturedIssues(), discoveryName(new AwsAccessKeyRule()));
        assertThat(awsIssue.detail())
                .contains("Found 1 AWS Access Keys finding in MCP discovery")
                .doesNotContain("finding(s)")
                .doesNotContain("discovery content");
    }

    @Test
    void detailUsesPluralWhenMultipleFindings() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(
                List.of(new AwsAccessKeyRule()), settings, api);
        McpToolDefinition toolA = new McpToolDefinition(
                "deploy", "Use AKIA234567ABCDEFGHIJ here", null);
        McpToolDefinition toolB = new McpToolDefinition(
                "release", "And ASIA234567ABCDEFGHIJ there", null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(toolA, toolB), List.of(), List.of(), List.of());

        scanner.scan(content, host, null);

        AuditIssue awsIssue = issueNamed(capturedIssues(), discoveryName(new AwsAccessKeyRule()));
        assertThat(awsIssue.detail())
                .contains("Found 2 AWS Access Keys findings in MCP discovery")
                .doesNotContain("finding(s)");
    }

    @Test
    void remediationLeadsWithActionAndDropsThreatModelNarration() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        AuditIssue awsIssue = issueNamed(capturedIssues(), discoveryName(new AwsAccessKeyRule()));
        assertThat(awsIssue.remediation())
                .contains("Revoke and rotate the exposed credential")
                .contains("Remove it from the MCP discovery metadata")
                .doesNotContain("handler")
                .doesNotContain("effectively disclosed");
    }

    @Test
    void rendersPerRuleReferencesInBackground() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        AuditIssue awsIssue = issueNamed(capturedIssues(), discoveryName(new AwsAccessKeyRule()));
        assertThat(awsIssue.detail()).doesNotContain("<b>References</b>");
        assertThat(awsIssue.definition().background())
                .contains("<b>References</b>")
                .contains("https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html")
                .contains("CWE-312");
    }

    @Test
    void masterToggleDisabledEmitsNothing() {
        when(settings.isEnabled("discovery-content-scanner", true)).thenReturn(false);
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        verify(siteMap, never()).add(any(AuditIssue.class));
    }

    @Test
    void iconContentRuleFiresForUnsafeSchemeIcon() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(
                List.of(new IconContentRule()), settings, api);
        McpToolDefinition tool = new McpToolDefinition(
                "logo", "desc", null,
                List.of(new IconDescriptor("file:///etc/passwd", "image/png", List.of())));
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());

        scanner.scan(content, host, null);

        List<AuditIssue> issues = capturedIssues();
        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).name()).isEqualTo(discoveryName(new IconContentRule()));
        assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void iconRemediationGivesIconGuidanceNotCredentialRotation() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(
                List.of(new IconContentRule()), settings, api);
        McpToolDefinition tool = new McpToolDefinition(
                "logo", "desc", null,
                List.of(new IconDescriptor("file:///etc/passwd", "image/png", List.of())));
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());

        scanner.scan(content, host, null);

        String remediation = capturedIssues().get(0).remediation().toLowerCase();
        assertThat(remediation).contains("https raster");
        assertThat(remediation).doesNotContain("revoke and rotate the exposed credential");
        assertThat(remediation).doesNotContain("no rotation is required");
    }

    @Test
    void infoDisclosureRemediationDoesNotMandateCredentialRotation() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(
                List.of(new EmailRule()), settings, api);
        McpToolDefinition tool = new McpToolDefinition(
                "support", "Contact security@acme.io", null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());

        scanner.scan(content, host, null);

        String remediation = capturedIssues().get(0).remediation().toLowerCase();
        assertThat(remediation).contains("no rotation is required");
        assertThat(remediation).doesNotContain("revoke");
    }

    @Test
    void credentialRemediationStillMandatesRotation() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(
                List.of(new AwsAccessKeyRule()), settings, api);
        McpToolDefinition tool = new McpToolDefinition(
                "deploy", "Use AKIA234567ABCDEFGHIJ here", null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());

        scanner.scan(content, host, null);

        String remediation = capturedIssues().get(0).remediation().toLowerCase();
        assertThat(remediation).contains("revoke and rotate the exposed credential");
    }

    @Test
    void everyIssueBackgroundCarriesCweAndReferences() {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(rules, settings, api);

        scanner.scan(seededContent(), host, null);

        List<AuditIssue> issues = capturedIssues();
        assertThat(issues).isNotEmpty();
        for (AuditIssue issue : issues) {
            assertThat(issue.definition().background())
                    .as("background for %s", issue.name())
                    .isNotEmpty()
                    .contains("CWE-")
                    .contains("<b>Vulnerability classifications</b>");
        }
    }

    @ParameterizedTest
    @MethodSource("ruleTriggers")
    void everyDefaultRuleEmitsIssueForKnownTrigger(RuleTrigger trigger) {
        DiscoveryContentScanner scanner = new DiscoveryContentScanner(
                List.of(trigger.rule()), settings, api);

        scanner.scan(trigger.content(), host, null);

        List<AuditIssue> issues = capturedIssues();
        assertThat(issues)
                .as("rule %s must emit an issue for its trigger", trigger.rule().id())
                .hasSize(1);
        assertThat(issues.get(0).name()).isEqualTo(discoveryName(trigger.rule()));
        assertThat(issues.get(0).severity()).isEqualTo(trigger.expectedSeverity());
    }

    private static Stream<RuleTrigger> ruleTriggers() {
        return Stream.of(
                fieldTrigger("discovery-content-scanner.email",
                        "Contact security@acme.io"),
                fieldTrigger("discovery-content-scanner.jwt",
                        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signaturePartIsLong"),
                fieldTrigger("discovery-content-scanner.aws-access-key",
                        "AKIA234567ABCDEFGHIJ"),
                fieldTrigger("discovery-content-scanner.github-pat",
                        "ghp_aB3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fG2H"),
                fieldTrigger("discovery-content-scanner.slack-token",
                        "xoxb-1234567890-1234567890-abcdefABCDEF0123456789ab"),
                fieldTrigger("discovery-content-scanner.ai-key",
                        "sk-proj-aB3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fGT3BlbkFJhJkMnPqRsTuVwXyZ012345678"),
                fieldTrigger("discovery-content-scanner.google-api-key",
                        "AIzaSyD3xZ9qWmK2vL7nP1rT5yU8iO4eC6sD0fG"),
                fieldTrigger("discovery-content-scanner.stripe-key",
                        "sk_live_aB3xZ9qWmK2vL7nP1rT5yU8i"),
                fieldTrigger("discovery-content-scanner.gcp-service-account",
                        "{\"type\":\"service_account\",\"project_id\":\"p\","
                                + "\"private_key\":\"-----BEGIN PRIVATE KEY-----\"}"),
                fieldTrigger("discovery-content-scanner.azure-connection-string",
                        "DefaultEndpointsProtocol=https;AccountName=acct;"
                                + "AccountKey=aZ3kP9mX7qW2vL8nR1tY5uH4eC6sD0fG2jK8lM4nB7vC9xQ1zA3wE5rT7yU2iO6pS8dF0gH==;"
                                + "EndpointSuffix=core.windows.net"),
                fieldTrigger("discovery-content-scanner.ssh-private-key",
                        "-----BEGIN RSA PRIVATE KEY-----\n"
                                + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb3xQ2mZ7vL3pN"),
                fieldTrigger("discovery-content-scanner.pgp-private-key",
                        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n"
                                + "lQVYBGV3xQ2mZ7vL3pNwT1yU6iO4eC0sD5fG2hJ4kL8mN3qZ7vL9pT1yU6iO4eC0"),
                fieldTrigger("discovery-content-scanner.credit-card",
                        "card 4532015112830366 saved"),
                fieldTrigger("discovery-content-scanner.private-ip",
                        "Backend reachable at http://192.168.1.10/internal."),
                iconTrigger()
        );
    }

    private static RuleTrigger fieldTrigger(String ruleId, String descriptionValue) {
        ContentRule rule = findRule(ruleId);
        McpToolDefinition tool = new McpToolDefinition("widget", descriptionValue, null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());
        return new RuleTrigger(rule, content, rule.severity());
    }

    private static RuleTrigger iconTrigger() {
        ContentRule rule = new IconContentRule();
        McpToolDefinition tool = new McpToolDefinition(
                "logo", "desc", null,
                List.of(new IconDescriptor("file:///etc/passwd", "image/png", List.of())));
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());
        return new RuleTrigger(rule, content, AuditIssueSeverity.HIGH);
    }

    private static ContentRule findRule(String id) {
        return ContentRules.all().stream()
                .filter(r -> r.id().equals(id))
                .findFirst()
                .orElseThrow(() -> new AssertionError("rule not registered: " + id));
    }

    private record RuleTrigger(ContentRule rule, DiscoveredContent content,
                               AuditIssueSeverity expectedSeverity) {
        @Override
        public String toString() {
            return rule.id();
        }
    }

    private DiscoveredContent seededContent() {
        ServerMetadata server = new ServerMetadata(
                Map.of("name", "demo", "version", "1.0"),
                "Auth via " + JWT_FIXTURE,
                Map.of());
        McpToolDefinition tool = new McpToolDefinition(
                "send_email", "Contact alice@acme.io for details", null);
        McpPromptDefinition prompt = new McpPromptDefinition(
                "rotate", "Use AKIA234567ABCDEFGHIJ to authenticate",
                List.of(new PromptArgument("region", "aws region", true)));
        return new DiscoveredContent(server, List.of(tool), List.of(), List.of(), List.of(prompt));
    }

    private List<AuditIssue> capturedIssues() {
        ArgumentCaptor<AuditIssue> captor = ArgumentCaptor.forClass(AuditIssue.class);
        verify(siteMap, atLeastOnce()).add(captor.capture());
        return captor.getAllValues();
    }

    private static AuditIssue issueNamed(List<AuditIssue> issues, String name) {
        return issues.stream()
                .filter(i -> name.equals(i.name()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no issue named " + name));
    }
}
