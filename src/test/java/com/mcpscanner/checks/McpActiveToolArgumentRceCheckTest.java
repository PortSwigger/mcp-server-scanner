package com.mcpscanner.checks;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionId;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.CurrentSelectionHolder;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveToolArgumentRceCheckTest {

    private static final String MCP_REQUEST_BODY = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}";

    private static final String TOOLS_LIST_WITH_CODE_ARG =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"format_quote\","
                    + "\"description\":\"Render quote\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"format\":{\"type\":\"string\",\"description\":\"Python expression to evaluate.\"}},"
                    + "\"required\":[\"format\"]}}]}}";

    private static final String TOOLS_LIST_WITHOUT_CODE_ARG =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"query_user\","
                    + "\"description\":\"Look up user\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"username\":{\"type\":\"string\",\"description\":\"User to find.\"}}}}]}}";

    private static final String TOOLS_LIST_TWO_CODE_TOOLS =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":["
                    + "{\"name\":\"format_quote\",\"description\":\"Render quote\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"format\":{\"type\":\"string\",\"description\":\"Expression\"}}}},"
                    + "{\"name\":\"run_script\",\"description\":\"Run a script\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"script\":{\"type\":\"string\",\"description\":\"Script body\"}}}}"
                    + "]}}";

    private static final String TOOLS_LIST_ANYOF_CODE_ARG =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"format_quote\","
                    + "\"description\":\"Render quote\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"format\":{\"anyOf\":[{\"type\":\"string\"},{\"type\":\"null\"}],"
                    + "\"description\":\"Python expression to evaluate.\"}},"
                    + "\"required\":[\"format\"]}}]}}";

    private static final String EMPTY_TOOL_CALL_BODY =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private AuditInsertionPoint insertionPoint;
    @Mock private Http http;
    @Mock private HttpRequest request;
    @Mock private HttpService httpService;
    @Mock private ScanCheckSettings settings;
    @Mock private McpEventLog eventLog;
    @Mock private CollaboratorClient collaboratorClient;

    private RecordingSleeper sleeper;
    private CountingSupplier<CollaboratorClient> collaboratorSupplier;
    private CurrentSelectionHolder selectionHolder;
    private McpActiveToolArgumentRceCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        sleeper = new RecordingSleeper();
        collaboratorSupplier = new CountingSupplier<>(() -> collaboratorClient);
        selectionHolder = new CurrentSelectionHolder();
        check = newCheckWith(collaboratorSupplier);
    }

    private static McpToolDefinition toolNamed(String name) {
        return new McpToolDefinition(name, "", "{}");
    }

    private void selectToolsByName(String... names) {
        McpToolDefinition[] tools = new McpToolDefinition[names.length];
        for (int i = 0; i < names.length; i++) {
            tools[i] = toolNamed(names[i]);
        }
        selectionHolder.set(ScanInventory.toolsOnly(List.of(tools)));
    }

    @Test
    void descriptor_exposesToolArgRceMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("tool-arg-rce");
        assertThat(descriptor.displayName()).isEqualTo("MCP Tool Argument Code Execution");
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.HIGH);
        // T-deadcheck: PER_HOST-only checks with no scan-start hook were never invoked by Burp's
        // audit pipeline. PER_REQUEST drives them; internal HostDedup keeps the battery single-fire.
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(descriptor.defaultEnabled()).isTrue();
    }

    @Test
    void dedupsRepeatedInsertionPointsAgainstSameHost() {
        // PER_REQUEST dispatch fires this self-discovering check once per insertion point; HostDedup
        // must run the Collaborator-backed battery once and skip the rest (no second discovery
        // request, no second payload mint).
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0);

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        int payloadsAfterFirst = issuer.generatedCount();
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isNotEmpty();
        assertThat(second.auditIssues()).isEmpty();
        assertThat(issuer.generatedCount())
                .as("second insertion point must not re-mint Collaborator payloads")
                .isEqualTo(payloadsAfterFirst);
    }

    @Test
    void clearSessionStateAllowsReprobeAfterReconnect() {
        // Parity with resource-traversal / unauth-discovery: a reconnect clears the per-host dedup
        // so the battery runs again against the same host.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        // After reconnect the battery re-mints a fresh payload batch; record an interaction for the
        // first payload of THAT batch so the second run can confirm a hit.
        issuer.recordInteractionFor(issuer.generatedCount());
        check.clearSessionState();
        AuditResult afterReconnect = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(afterReconnect.auditIssues()).isNotEmpty();
    }

    @Test
    void transientHttpLayerErrorReleasesClaimSoNextInsertionPointReprobes() {
        // A transient HTTP-layer failure (timeout / dropped stream) on the FIRST insertion point
        // means discovery never reached the server. The check must release the host claim so a
        // later insertion point on the same host retries the battery.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        boolean[] firstAttempt = {true};
        stubResponses(body -> {
            if (firstAttempt[0]) {
                return transientFailure();
            }
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0);

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        firstAttempt[0] = false;
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isEmpty();
        assertThat(second.auditIssues()).isNotEmpty();
    }

    @Test
    void transientCollaboratorUnavailabilityReleasesClaimSoNextInsertionPointReprobes() {
        // A transient Collaborator hiccup (supplier returns null this time) must NOT claim-and-
        // never-retry: the host claim is released so a later insertion point retries once
        // Collaborator is back, rather than silently disabling RCE for the rest of the scan.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0);
        boolean[] collaboratorDown = {true};
        check = newCheckWith(new CountingSupplier<>(
                () -> collaboratorDown[0] ? null : collaboratorClient));

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        collaboratorDown[0] = false;
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isEmpty();
        assertThat(second.auditIssues()).isNotEmpty();
    }

    @Test
    void doCheck_returnsEmptyWhenDisabled() {
        when(settings.isEnabled("tool-arg-rce", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void firesHighSeverityFirmConfidenceForDnsOnlyInteraction() {
        // A DNS-only Collaborator interaction is strong evidence of code execution
        // but has narrow alternative explanations (shared resolver, DNS prefetch),
        // so the confidence is FIRM, not CERTAIN.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP Tool Argument Code Execution");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("format_quote::format");
        // Per-hit line: language + plain callback wording + injected expression,
        // never the internal payload label or Collaborator jargon.
        assertThat(issue.detail()).contains("Node.js payload triggered a DNS callback");
        assertThat(issue.detail()).contains(".lookup(");
        assertThat(issue.detail()).contains("oastify.example");
        // The detail explains why a DNS-only interaction is reported as FIRM.
        assertThat(issue.detail()).contains("Only a DNS lookup");
        assertThat(issue.detail()).contains("Firm rather than Certain");
        assertThat(issue.detail()).doesNotContain("NODE_DNS_LOOKUP");
        assertThat(issue.detail()).doesNotContain("interaction:");
        assertThat(issue.detail()).doesNotContain("code-hinted");
        assertThat(sleeper.slept).isTrue();
    }

    @Test
    void firesHighSeverityCertainConfidenceForHttpInteraction() {
        // A full HTTP callback to the unique payload host is unequivocal code
        // execution, so the confidence is CERTAIN.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0, InteractionType.HTTP);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
        assertThat(issue.detail()).contains("full HTTP callback");
        assertThat(issue.detail()).contains("confirmed arbitrary code execution");
        assertThat(issue.detail()).doesNotContain("Firm rather than Certain");
    }

    @Test
    void doesNotFireWhenCollaboratorReportsNoInteractions() {
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        stubCollaboratorClient(new InteractionIssuer());
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void skipsAndLogsWhenSupplierReturnsNull() {
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        stubResponses(body -> successBody(TOOLS_LIST_WITH_CODE_ARG));
        check = newCheckWith(new CountingSupplier<>(() -> null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(eventLog).info(org.mockito.ArgumentMatchers.contains("Collaborator unavailable"));
    }

    @Test
    void skipsAndLogsWhenSupplierThrows() {
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        stubResponses(body -> successBody(TOOLS_LIST_WITH_CODE_ARG));
        check = newCheckWith(new CountingSupplier<>(() -> {
            throw new IllegalStateException("collaborator disabled");
        }));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(eventLog).info(org.mockito.ArgumentMatchers.contains("Collaborator unavailable"));
    }

    @Test
    void doesNotFireProbesWhenNoToolsHaveCodeHintedArgs() {
        selectToolsByName("query_user");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> successBody(TOOLS_LIST_WITHOUT_CODE_ARG));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        assertThat(issuer.generatedCount()).isZero();
    }

    @Test
    void groupsMultipleInteractionsByToolArgLanguageTuple() {
        selectToolsByName("format_quote", "run_script");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_TWO_CODE_TOOLS);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        // Two different probes get interactions: index 0 (first tool, first payload)
        // and an index hitting the second tool's first payload (offset = payload count).
        issuer.recordInteractionFor(0);
        issuer.recordInteractionFor(ToolArgRcePayloads.all().size());

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(2);
        assertThat(result.auditIssues()).extracting(AuditIssue::detail)
                .anyMatch(detail -> detail.contains("format_quote::format"))
                .anyMatch(detail -> detail.contains("run_script::script"));
    }

    @Test
    void capsCollaboratorPayloadsAtConfiguredMaximum() {
        String[] manyToolNames = new String[12];
        for (int i = 0; i < manyToolNames.length; i++) {
            manyToolNames[i] = "tool_" + i;
        }
        selectToolsByName(manyToolNames);
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        String manyToolsBody = manyCodeToolsBody(12);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(manyToolsBody);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });

        check.doCheck(baseRequestResponse, insertionPoint, http);

        // 12 args x 9 templates = 108 would-be probes; capped at MAX_PROBES_PER_SCAN.
        assertThat(issuer.generatedCount())
                .isEqualTo(McpActiveToolArgumentRceCheck.MAX_PROBES_PER_SCAN);
        verify(eventLog).info(org.mockito.ArgumentMatchers.contains("probe cap reached at "
                + McpActiveToolArgumentRceCheck.MAX_PROBES_PER_SCAN));
    }

    @Test
    void doesNotFireForNonMcpRequest() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{\"hello\":\"world\"}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void doesNotMintCollaboratorClientWhenNoToolsSelected() {
        // Destructive-scan protection invariant: with no tools selected the check
        // must return before invoking the Collaborator supplier — so zero
        // Collaborator payloads can be minted against the live host.
        stubMcpBaselineRequest();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        assertThat(collaboratorSupplier.callCount.get()).isZero();
        verify(http, never()).sendRequest(any(HttpRequest.class));
        verify(eventLog).info(org.mockito.ArgumentMatchers.contains("no tools selected"));
    }

    @Test
    void filtersDiscoveredToolsToUserSelectionBeforeMintingPayloads() {
        // Discovery returns format_quote AND run_script, but only format_quote is
        // selected — Collaborator payloads must be minted ONLY for format_quote.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_TWO_CODE_TOOLS);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).detail()).contains("format_quote::format");
        assertThat(result.auditIssues().get(0).detail()).doesNotContain("run_script");
        // Only format_quote::format is probed: payloadCount payloads minted.
        assertThat(issuer.generatedCount()).isEqualTo(ToolArgRcePayloads.all().size());
        verify(http, never()).sendRequest(org.mockito.ArgumentMatchers.argThat(
                req -> req != null && req.bodyToString().contains("\"run_script\"")));
    }

    @Test
    void capturesLateArrivingCollaboratorInteraction() {
        // Poll with deadline, not one-shot. First poll returns empty,
        // second returns the matching interaction — issue must still fire.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        lenient().when(collaboratorClient.generatePayload()).thenAnswer(invocation -> issuer.mintPayload());
        AtomicInteger pollCount = new AtomicInteger();
        lenient().when(collaboratorClient.getAllInteractions()).thenAnswer(invocation -> {
            int call = pollCount.incrementAndGet();
            if (call == 1) {
                return List.of();
            }
            return issuer.interactions();
        });
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(pollCount.get()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void failsClosedWhenGeneratePayloadThrows() {
        // A quota/runtime failure mid-loop must abort cleanly with one
        // log line — not hard-error the check, and not keep calling the failing client.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        when(collaboratorClient.generatePayload())
                .thenThrow(new RuntimeException("collaborator quota exhausted"));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(collaboratorClient, times(1)).generatePayload();
        verify(collaboratorClient, never()).getAllInteractions();
        verify(eventLog).info(org.mockito.ArgumentMatchers.contains("payload generation failed"));
    }

    @Test
    void capsEvidenceAtFiveInteractions() {
        // Cap evidence at 5 request/response pairs per issue,
        // mirroring McpActiveToolArgumentPathTraversalCheck. With all 9
        // payload templates firing on the single code arg format_quote::format,
        // we get more than 5 confirmed hits on the same (tool, arg) group.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        for (int i = 0; i < ToolArgRcePayloads.all().size(); i++) {
            issuer.recordInteractionFor(i);
        }

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.requestResponses()).hasSize(5);
        int totalHits = ToolArgRcePayloads.all().size();
        assertThat(issue.detail()).contains((totalHits - 5) + " additional");
    }

    @Test
    void doesNotObtainCollaboratorClientWhenNoCodeLikeArgs() {
        // Discover and filter BEFORE obtaining a Collaborator client.
        // Selection is non-empty (so the non-empty-selection gate passes), but the
        // discovered tool has no code-hinted args — supplier must never be called.
        selectToolsByName("query_user");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITHOUT_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        assertThat(collaboratorSupplier.callCount.get()).isZero();
    }

    @Test
    void defaultPollScheduleMatchesEscalatingDeadlineContract() {
        // Lock the production escalating poll schedule so a
        // refactor to a single value or a different total deadline trips this
        // test. The schedule is the whole point of deadline-bounded
        // polling and must remain testable rather than hidden behind a
        // Duration-as-sentinel.
        List<Duration> schedule = McpActiveToolArgumentRceCheck.DEFAULT_POLL_SCHEDULE;

        assertThat(schedule).containsExactly(
                Duration.ofMillis(250),
                Duration.ofMillis(500),
                Duration.ofMillis(1000),
                Duration.ofMillis(1500),
                Duration.ofMillis(1750));
        Duration total = schedule.stream().reduce(Duration.ZERO, Duration::plus);
        assertThat(total).isEqualTo(Duration.ofMillis(5000));
    }

    @Test
    void firesForAnyOfStringCodeArgumentSchema() {
        // Real-world tool schemas use anyOf/oneOf composition for
        // optional/nullable strings — the legacy
        // schema.path("type").asText().equals("string") check would skip them.
        selectToolsByName("format_quote");
        stubMcpBaselineRequest();
        InteractionIssuer issuer = new InteractionIssuer();
        stubCollaboratorClient(issuer);
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_ANYOF_CODE_ARG);
            }
            return successBody(EMPTY_TOOL_CALL_BODY);
        });
        issuer.recordInteractionFor(0);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).detail()).contains("format_quote::format");
    }

    private McpActiveToolArgumentRceCheck newCheckWith(Supplier<CollaboratorClient> supplier) {
        return new McpActiveToolArgumentRceCheck(
                settings, eventLog, supplier, selectionHolder, sleeper,
                List.of(Duration.ofMillis(1), Duration.ofMillis(1), Duration.ofMillis(1),
                        Duration.ofMillis(1), Duration.ofMillis(1)));
    }

    private void stubMcpBaselineRequest() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(MCP_REQUEST_BODY);
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(httpService.host()).thenReturn("localhost");
        lenient().when(httpService.port()).thenReturn(8080);
    }

    private void stubResponses(Function<String, HttpRequestResponse> responseFn) {
        when(request.withBody(anyString())).thenAnswer(invocation -> requestWithBody(invocation.getArgument(0)));
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            return responseFn.apply(sent.bodyToString());
        });
    }

    private void stubCollaboratorClient(InteractionIssuer issuer) {
        lenient().when(collaboratorClient.generatePayload()).thenAnswer(invocation -> issuer.mintPayload());
        lenient().when(collaboratorClient.getAllInteractions()).thenAnswer(invocation -> issuer.interactions());
    }

    private static String manyCodeToolsBody(int toolCount) {
        StringBuilder body = new StringBuilder("{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[");
        for (int i = 0; i < toolCount; i++) {
            if (i > 0) {
                body.append(",");
            }
            body.append("{\"name\":\"tool_").append(i).append("\",")
                    .append("\"description\":\"Tool ").append(i).append("\",")
                    .append("\"inputSchema\":{\"type\":\"object\",\"properties\":{")
                    .append("\"script\":{\"type\":\"string\",\"description\":\"Script.\"}}}}");
        }
        body.append("]}}");
        return body.toString();
    }

    private static HttpRequest requestWithBody(String body) {
        HttpRequest mutated = mock(HttpRequest.class);
        lenient().when(mutated.bodyToString()).thenReturn(body);
        return mutated;
    }

    private static HttpRequestResponse successBody(String responseBody) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.bodyToString()).thenReturn(responseBody);
        return rr;
    }

    /** A transport-layer failure: Burp returns an HttpRequestResponse with a null response. */
    private static HttpRequestResponse transientFailure() {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        lenient().when(rr.response()).thenReturn(null);
        return rr;
    }

    private static final class RecordingSleeper implements Sleeper {
        boolean slept = false;

        @Override
        public void sleep(Duration duration) {
            slept = true;
        }
    }

    private static final class CountingSupplier<T> implements Supplier<T> {
        private final Supplier<T> delegate;
        private final AtomicInteger callCount = new AtomicInteger();

        CountingSupplier(Supplier<T> delegate) {
            this.delegate = delegate;
        }

        @Override
        public T get() {
            callCount.incrementAndGet();
            return delegate.get();
        }
    }

    private static final class InteractionIssuer {
        private final List<String> issuedIds = new ArrayList<>();
        private final java.util.Map<Integer, InteractionType> scheduledInteractionIndices =
                new java.util.LinkedHashMap<>();

        CollaboratorPayload mintPayload() {
            String id = "iid-" + issuedIds.size();
            issuedIds.add(id);
            CollaboratorPayload payload = mock(CollaboratorPayload.class);
            InteractionId payloadId = mock(InteractionId.class);
            lenient().when(payloadId.toString()).thenReturn(id);
            lenient().when(payload.id()).thenReturn(payloadId);
            lenient().when(payload.toString()).thenReturn(id + ".oastify.example");
            return payload;
        }

        void recordInteractionFor(int payloadIndex) {
            recordInteractionFor(payloadIndex, InteractionType.DNS);
        }

        void recordInteractionFor(int payloadIndex, InteractionType type) {
            scheduledInteractionIndices.put(payloadIndex, type);
        }

        List<Interaction> interactions() {
            List<Interaction> resolved = new ArrayList<>(scheduledInteractionIndices.size());
            for (java.util.Map.Entry<Integer, InteractionType> entry : scheduledInteractionIndices.entrySet()) {
                int index = entry.getKey();
                if (index < issuedIds.size()) {
                    resolved.add(mockInteraction(issuedIds.get(index), entry.getValue()));
                }
            }
            return resolved;
        }

        int generatedCount() {
            return issuedIds.size();
        }

        private static Interaction mockInteraction(String id, InteractionType type) {
            Interaction interaction = mock(Interaction.class);
            InteractionId interactionId = mock(InteractionId.class);
            lenient().when(interactionId.toString()).thenReturn(id);
            lenient().when(interaction.id()).thenReturn(interactionId);
            lenient().when(interaction.type()).thenReturn(type);
            lenient().when(interaction.timeStamp()).thenReturn(ZonedDateTime.now());
            lenient().when(interaction.dnsDetails()).thenReturn(Optional.empty());
            lenient().when(interaction.httpDetails()).thenReturn(Optional.empty());
            return interaction;
        }
    }
}
