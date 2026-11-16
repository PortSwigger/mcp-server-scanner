package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.api.SettlingLateIssues;
import com.mcpscanner.checks.shared.collaborator.TestWatches;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.testutil.BurpArgumentPoint;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CommandInjectionCheckTest {

    private static final ArithmeticCanary CANARY = new ArithmeticCanary(123_456_789L, 987_654_321L);

    private static final String SUBJECT_TAIL = " of tools/call ping_host at " + SimulatedToolServer.ENDPOINT;
    private static final String HOST_FIELD = "field MCP field: params.arguments.host" + SUBJECT_TAIL;

    private final FakeCollaborator collaborator = new FakeCollaborator();
    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsAShellThatComputesTheArithmeticWhileTheMatchedControlSucceedsWithoutIt() {
        List<AuditIssue> issues = audit(new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP OS command injection");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("ping_host").contains("params.arguments.host")
                    .contains("shell arithmetic expansion").contains("matched control");
            assertThat(issue.requestResponses()).hasSize(5);
        });
    }

    @Test
    void highlightsTheInsertedPayloadAndTheComputedResultInTheEvidence() {
        List<AuditIssue> issues = audit(new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine()));

        HttpRequestResponse injected = issues.get(0).requestResponses().get(1);
        assertThat(markedTexts(injected.request().toByteArray(), injected.requestMarkers()))
                .singleElement().asString().contains(CANARY.command());
        assertThat(markedTexts(injected.response().toByteArray(), injected.responseMarkers()))
                .isNotEmpty().allMatch(CANARY.result()::equals);
    }

    private static List<String> markedTexts(burp.api.montoya.core.ByteArray message,
                                            List<burp.api.montoya.core.Marker> markers) {
        String text = new String(message.getBytes(), java.nio.charset.StandardCharsets.UTF_8);
        return markers.stream().map(marker -> text.substring(marker.range().startIndexInclusive(),
                marker.range().endIndexExclusive())).toList();
    }

    @Test
    void reportsThroughTheQuotedLiteralControlWhenValidationRejectsTheMatchedControl() {
        SimulatedToolServer server = new SimulatedToolServer("advanced_search", "fileType",
                ToolBehaviours.shellCommandLineAllowingFirstToken(SimulatedToolServer.BASE_VALUE));

        List<AuditIssue> issues = audit(server);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP OS command injection");
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("quoted-literal control");
            assertThat(issue.requestResponses()).hasSize(6);
        });
        assertThat(server.receivedValues()).contains(SimulatedToolServer.BASE_VALUE + "$(" + CANARY.quotedCommand() + ")");
    }

    private static final String USAGE = "Display resources.\n\nOptions:\n  -A, --all-namespaces=false: list across "
            + "namespaces\n  -o, --output='': output format\n  -l, --selector='': label query\n\nUsage:\n  "
            + "program get [flags]";

    @Test
    void reportsAFieldParsedAsAnOptionWhenHelpPrintsOptionsTheBaselineAndControlLack() {
        SimulatedToolServer server = new SimulatedToolServer("get_resource", "name",
                ToolBehaviours.optionParsingProgram(USAGE, "error: unknown flag: --version"));

        List<AuditIssue> issues = audit(server);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP argument injection");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("command-line option injection").contains("--help")
                    .contains("--all-namespaces").contains("language model");
            assertThat(issue.requestResponses()).hasSize(4);
        });
        assertThat(server.receivedValues()).contains("--help", "help");
    }

    @Test
    void reportsAFieldParsedAsAnOptionWhenVersionPrintsAVersionNumberTheBaselineAndControlLack() {
        List<AuditIssue> issues = audit(new SimulatedToolServer("get_resource", "name",
                ToolBehaviours.optionParsingProgram("error: unknown flag: --help", "Client Version: v1.35.6")));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP argument injection");
            assertThat(issue.detail()).contains("--version").contains("1.35.6");
        });
    }

    @Test
    void reportsAProgramThatPrintsUsageForAnyUnknownOption() {
        assertThat(audit(new SimulatedToolServer("get_resource", "name",
                ToolBehaviours.optionParsingProgramPrintingUsageOnAnyUnknownFlag(USAGE))))
                .extracting(AuditIssue::name).containsExactly("MCP argument injection");
    }

    @Test
    void staysSilentWhenEveryUnmatchedValuePrintsTheSameUsage() {
        assertThat(audit(new SimulatedToolServer("get_resource", "name",
                ToolBehaviours.printingUsageForAnyUnknownValue(USAGE)))).isEmpty();
    }

    @Test
    void staysSilentWhenTheDashedValueReturnsADifferentVersionEachTime() {
        assertThat(audit(new SimulatedToolServer("get_resource", "name",
                ToolBehaviours.answeringADashedValueWithAFreshVersion()))).isEmpty();
    }

    @Test
    void staysSilentWhenEveryReplyNamesTheSameVersion() {
        assertThat(audit(new SimulatedToolServer("get_resource", "name",
                ToolBehaviours.namingItsVersionInEveryReply("1.4.2")))).isEmpty();
    }

    @Test
    void staysSilentWhenTheValueIsPassedAsAnArgumentVectorEntry() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.argumentVector());

        assertThat(audit(server)).isEmpty();
        assertThat(server.receivedValues()).noneMatch(value -> value.contains(FakeCollaborator.DOMAIN));
    }

    @Test
    void probesOutOfBandOnlyWhenCollaboratorIsAvailable() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.argumentVector());

        audit(server, Optional::empty);

        assertThat(server.receivedValues()).noneMatch(value -> value.contains("nslookup"));
        assertThat(skipLines()).containsExactly("skipped the out-of-band probes of " + HOST_FIELD
                + " (prerequisite missing: Burp Collaborator is unavailable)");
    }

    @Test
    void reportsAFieldThatIsItselfACommandAsInformationAndSendsNoCollaboratorProbe() {
        SimulatedToolServer server = new SimulatedToolServer("run_command", "command", ToolBehaviours.commandRunner());

        assertThat(audit(server)).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP command execution argument");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        });
        assertThat(server.receivedValues()).noneMatch(value -> value.contains("nslookup"));
        assertThat(server.receivedValues()).contains(CANARY.command());
    }

    @Test
    void staysSilentForAToolThatOnlyReflectsItsInput() {
        assertThat(audit(new SimulatedToolServer("echo", "message", ToolBehaviours.reflecting()))).isEmpty();
    }

    @Test
    void makesNoInBandClaimWhenTheMatchedControlIsRejectedAndQuotedArithmeticStillExpands() {
        SimulatedToolServer server = new SimulatedToolServer("render", "text",
                ToolBehaviours.rejectingTheMatchedControl(ToolBehaviours.arithmeticTemplateThenShell()));

        assertThat(audit(server)).isEmpty();
    }

    @Test
    void reportsCodeInjectionWhenTheValueIsSplicedIntoAStringLiteral() {
        List<AuditIssue> issues = audit(new SimulatedToolServer("greet", "name",
                ToolBehaviours.pythonSingleQuotedStringEvaluator()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP code injection");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("Python single-quoted string breakout");
            assertThat(issue.requestResponses()).hasSize(5);
        });
    }

    @Test
    void reportsAnEvaluatorWithoutCodeLikeNamesAsInformationOnly() {
        List<AuditIssue> issues = audit(new SimulatedToolServer("evaluate", "expression",
                ToolBehaviours.pythonEvaluator()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP code execution argument");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("Python expression");
            assertThat(issue.requestResponses()).hasSize(4);
        });
    }

    @Test
    void reportsAnIntendedCodeRunnerAsInformationOnly() {
        List<AuditIssue> issues = audit(new SimulatedToolServer("run_python", "code", ToolBehaviours.pythonEvaluator()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP code execution argument");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        });
    }

    @Test
    void reportsAJavaScriptTemplateLiteralEvaluator() {
        List<AuditIssue> issues = audit(new SimulatedToolServer("render_greeting", "template",
                ToolBehaviours.javascriptTemplate()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP code injection");
            assertThat(issue.detail()).contains("JavaScript template literal interpolation");
        });
    }

    @Test
    void readsServerSentEventReplies() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine())
                .replyingWithSse();

        assertThat(audit(server)).extracting(AuditIssue::name).containsExactly("MCP OS command injection");
    }

    @Test
    void reportsAShellReconstructedCollaboratorHostname() {
        SimulatedToolServer server = new SimulatedToolServer("archive", "label",
                ToolBehaviours.blindShell(collaborator::resolve));

        List<AuditIssue> issues = audit(server);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP OS command injection");
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("Collaborator DNS interaction")
                    .contains("Collaborator interactions: DNS interaction from 127.0.0.1 at");
            assertThat(issue.requestResponses()).isNotEmpty();
        });
    }

    @Test
    void neverSendsTheCollaboratorHostnameUnsplit() {
        SimulatedToolServer server = new SimulatedToolServer("archive", "label",
                ToolBehaviours.blindShell(collaborator::resolve));

        audit(server);

        assertThat(collaborator.generatedHosts()).hasSize(ShellBreakout.values().length);
        assertThat(server.receivedValues()).noneMatch(value -> collaborator.generatedHosts().stream()
                .anyMatch(value::contains));
    }

    @Test
    void ignoresCollaboratorInteractionsForOtherPayloads() {
        collaborator.recordUnrelated("someone-else");
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.argumentVector());

        assertThat(audit(server)).isEmpty();
    }

    @Test
    void probesInBandWhenTheBaselineIsAnsweredWithAToolError() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host",
                ToolBehaviours.shellFailingUnlessACommandRan());

        assertThat(audit(server)).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP OS command injection");
            assertThat(issue.detail()).contains("quoted-literal control");
        });
    }

    @Test
    void probesOnlyOutOfBandWhenTheBaselineIsNotAJsonRpcReply() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine());
        HttpRequestResponse base = server.baseline();
        HttpRequestResponse failed = HttpRequestResponse.httpRequestResponse(base.request(),
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse("HTTP/1.1 500 X\r\n\r\noops"));

        check(collaborator::available).audit(failed, server.argumentField(base), server.http());

        assertThat(server.receivedValues()).noneMatch(value -> value.contains("printf"));
        assertThat(server.receivedValues()).anyMatch(value -> value.contains("nslookup"));
        assertThat(skipLines()).containsExactly("skipped the in-band probes of " + HOST_FIELD
                + " (prerequisite missing: the baseline got no JSON-RPC reply)");
    }

    @Test
    void reportsACollaboratorCallbackThatArrivesAfterTheAuditReturned() {
        java.util.List<String> lateHosts = new java.util.ArrayList<>();
        SimulatedToolServer blind = new SimulatedToolServer("archive", "label", ToolBehaviours.blindShell(lateHosts::add));
        CollaboratorWatch watch = TestWatches.immediate(collaborator::available);
        SettlingLateIssues late = new SettlingLateIssues(watch);
        CommandInjectionCheck check = new CommandInjectionCheck(() -> CANARY, watch, late,
                BurpNativeJsonRpcFields.ABSENT, eventLog);
        HttpRequestResponse base = blind.baseline();

        assertThat(check.audit(base, blind.argumentField(base), blind.http())).isEmpty();
        assertThat(late.settle(check)).isEmpty();
        lateHosts.forEach(collaborator::resolve);

        assertThat(late.settle(check)).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP OS command injection");
            assertThat(issue.detail()).contains("archive").contains("params.arguments.label");
        });
        assertThat(late.settle(check)).isEmpty();
    }

    @Test
    void reusesOneCollaboratorClientAcrossFields() {
        java.util.concurrent.atomic.AtomicInteger supplied = new java.util.concurrent.atomic.AtomicInteger();
        SettledCheck check = check(() -> {
            supplied.incrementAndGet();
            return collaborator.available();
        });
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.argumentVector());
        HttpRequestResponse base = server.baseline();

        check.audit(base, server.argumentField(base), server.http());
        check.audit(base, server.argumentField(base), server.http());

        assertThat(supplied).hasValue(1);
    }

    @Test
    void sendsNoNewlineBreakoutIntoAHeaderField() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.argumentVector());
        HttpRequestResponse base = server.baseline();
        AuditInsertionPoint header = mock(AuditInsertionPoint.class);
        when(header.name()).thenReturn("MCP header: Mcp-Session-Id");
        when(header.baseValue()).thenReturn("session");
        when(header.type()).thenReturn(burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType.HEADER);
        java.util.List<String> payloads = new java.util.ArrayList<>();
        when(header.buildHttpRequestWithPayload(any())).thenAnswer(invocation -> {
            payloads.add(invocation.getArgument(0).toString());
            return base.request();
        });

        check(collaborator::available).audit(base, header, server.http());

        assertThat(payloads).isNotEmpty().noneMatch(payload -> payload.contains("\n"));
    }

    @Test
    void probesANotificationOutOfBandOnly() {
        SimulatedToolServer server = new SimulatedToolServer("ignored", "ignored", ToolBehaviours.reflecting());
        HttpRequestResponse base = server.notificationBase();
        AuditInsertionPoint field = server.field(base, "params.progressToken");

        check(collaborator::available).audit(base, field, server.http());

        assertThat(server.receivedValues()).hasSize(ShellBreakout.values().length)
                .allMatch(value -> value.contains("nslookup"));
    }

    @Test
    void stopsProbingAFieldAfterTwoConsecutiveProbesGetNoResponse() {
        SimulatedToolServer server = new SimulatedToolServer("slow", "value", ToolBehaviours.shellCommandLine());
        HttpRequestResponse base = server.baseline();
        Http timingOut = mock(Http.class);
        when(timingOut.sendRequest(any(HttpRequest.class)))
                .thenAnswer(invocation -> HttpRequestResponse.httpRequestResponse(invocation.getArgument(0), null));

        check(collaborator::available).audit(base, server.argumentField(base), timingOut);

        verify(timingOut, org.mockito.Mockito.times(2)).sendRequest(any(HttpRequest.class));
        assertThat(collaborator.generatedHosts()).isEmpty();
        assertThat(skipLines()).containsExactly("stopped field MCP field: params.arguments.value of tools/call slow at "
                + SimulatedToolServer.ENDPOINT + " (transport failure: 2 consecutive probes got no response)");
    }

    @Test
    void keepsProbingWhenOnlyOneProbeInARowGoesUnanswered() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine());
        HttpRequestResponse base = server.baseline();
        Http live = server.http();
        java.util.concurrent.atomic.AtomicInteger sent = new java.util.concurrent.atomic.AtomicInteger();
        Http everyOtherDropped = mock(Http.class);
        when(everyOtherDropped.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> sent.incrementAndGet() % 2 == 1
                ? HttpRequestResponse.httpRequestResponse(invocation.getArgument(0), null)
                : live.sendRequest(invocation.getArgument(0)));

        check(collaborator::available).audit(base, server.argumentField(base), everyOtherDropped);

        assertThat(sent.get()).isGreaterThan(2);
    }

    @Test
    void ignoresRequestsThatAreNotMcp() {
        Http http = mock(Http.class);
        HttpRequest request = ImmutableHttpRequest.post(SimulatedToolServer.ENDPOINT,
                Map.of("Content-Type", "text/plain"), "hello");
        AuditInsertionPoint point = mock(AuditInsertionPoint.class);

        when(point.name()).thenReturn("body");

        assertThat(check(collaborator::available).audit(HttpRequestResponse.httpRequestResponse(request, null), point,
                http)).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
        assertThat(skipLines()).singleElement().asString().startsWith("skipped field body of ")
                .endsWith(" (not applicable: not an MCP request)");
    }

    @Test
    void sendsTheBaseRequestWhenNoBaselineResponseWasCaptured() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine());
        HttpRequestResponse captured = server.baseline();
        HttpRequestResponse unanswered = HttpRequestResponse.httpRequestResponse(captured.request(), null);

        List<AuditIssue> issues = check(collaborator::available).audit(unanswered, server.argumentField(captured),
                server.http());

        assertThat(issues).hasSize(1);
    }

    @Test
    void survivesACollaboratorThatCannotBeReached() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.argumentVector());
        when(collaborator.client().generatePayload()).thenThrow(new IllegalStateException("Collaborator disabled"));

        assertThat(audit(server)).isEmpty();
        assertThat(skipLines()).containsExactly("skipped the out-of-band probes of " + HOST_FIELD
                + " (prerequisite missing: Burp Collaborator issued no payload)");
    }

    @Test
    void stopsProbingAFieldInBandAtTheFirstHttp429() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine());
        HttpRequestResponse base = server.baseline();
        Http rateLimiting = rateLimiting();

        assertThat(check(collaborator::available).audit(base, server.argumentField(base), rateLimiting)).isEmpty();

        verify(rateLimiting, org.mockito.Mockito.times(1)).sendRequest(any(HttpRequest.class));
        assertThat(collaborator.generatedHosts()).isEmpty();
        assertThat(skipLines()).containsExactly(
                "stopped " + HOST_FIELD + " (rate limited: the server answered HTTP 429)");
    }

    @Test
    void stopsTheOutOfBandProbesAtTheFirstHttp429AndStillWatchesThePayloadAlreadySent() {
        SimulatedToolServer server = new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine());
        HttpRequestResponse base = server.baseline();
        HttpRequestResponse failed = HttpRequestResponse.httpRequestResponse(base.request(),
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse("HTTP/1.1 500 X\r\n\r\noops"));
        Http rateLimiting = rateLimiting();
        CollaboratorWatch watch = TestWatches.immediate(collaborator::available);
        CommandInjectionCheck check = new CommandInjectionCheck(() -> CANARY, watch, new SettlingLateIssues(watch),
                BurpNativeJsonRpcFields.ABSENT, eventLog);

        assertThat(check.audit(failed, server.argumentField(base), rateLimiting)).isEmpty();

        verify(rateLimiting, org.mockito.Mockito.times(1)).sendRequest(any(HttpRequest.class));
        assertThat(watch.watchedCount()).isEqualTo(1);
        assertThat(skipLines()).endsWith(
                "stopped " + HOST_FIELD + " (rate limited: the server answered HTTP 429)");
    }

    @Test
    void keepsOneIssuePerOperationFieldAndName() {
        AuditIssue first = audit(new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine())).get(0);
        AuditIssue again = audit(new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine())).get(0);
        AuditIssue otherField = audit(new SimulatedToolServer("ping_host", "target",
                ToolBehaviours.shellCommandLine())).get(0);
        SettledCheck check = check(collaborator::available);

        assertThat(check.consolidate(first, again)).isEqualTo(ConsolidationAction.KEEP_EXISTING);
        assertThat(check.consolidate(first, otherField)).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    @Test
    void isDiscoveredFromTheCatalogAsAnInsertionPointCheck() {
        assertThat(CheckCatalog.discover(CheckServices.standalone()).find("command-injection"))
                .hasValueSatisfying(check -> assertThat(check.descriptor().kind()).isEqualTo(CheckKind.INSERTION_POINT));
    }

    @Test
    void namesBurpsSameKeyedArgumentPointsByTheirFullPathsAndKeepsAnIssueForEach() {
        AuditIssue source = burpPointIssue("source.path", "dest.path");
        AuditIssue dest = burpPointIssue("dest.path", "source.path");

        assertThat(source.detail()).contains("field: MCP field: params.arguments.source.path.");
        assertThat(dest.detail()).contains("field: MCP field: params.arguments.dest.path.");
        assertThat(check(collaborator::available).consolidate(source, dest))
                .isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    private AuditIssue burpPointIssue(String vulnerable, String sibling) {
        SimulatedToolServer server = new SimulatedToolServer("copy_file", vulnerable,
                ToolBehaviours.shellCommandLine()).alongside(sibling);
        HttpRequestResponse base = server.baseline();
        AuditInsertionPoint point = new BurpArgumentPoint(base.request(),
                ("arguments." + vulnerable).split("\\."));
        List<AuditIssue> issues = check(collaborator::available).audit(base, point, server.http());
        assertThat(issues).hasSize(1);
        return issues.get(0);
    }

    private List<AuditIssue> audit(SimulatedToolServer server) {
        return audit(server, collaborator::available);
    }

    private List<AuditIssue> audit(SimulatedToolServer server,
                                   Supplier<Optional<CollaboratorClient>> client) {
        HttpRequestResponse base = server.baseline();
        return check(client).audit(base, server.argumentField(base), server.http());
    }

    private SettledCheck check(Supplier<Optional<CollaboratorClient>> client) {
        CollaboratorWatch watch = TestWatches.immediate(client);
        SettlingLateIssues settling = new SettlingLateIssues(watch);
        return new SettledCheck(new CommandInjectionCheck(() -> CANARY, watch, settling,
                BurpNativeJsonRpcFields.PRESENT, eventLog), settling);
    }

    private static Http rateLimiting() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> HttpRequestResponse.httpRequestResponse(
                invocation.getArgument(0), burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nslow down")));
        return http;
    }

    private List<String> skipLines() {
        String prefix = CheckLog.prefix(CommandInjectionDescriptor.DESCRIPTOR.id());
        return eventLog.snapshot().stream()
                .filter(entry -> entry.level() == McpEventLog.Level.INFO)
                .map(McpEventLog.LogEntry::message)
                .filter(message -> message.startsWith(prefix))
                .map(message -> message.substring(prefix.length()))
                .filter(line -> line.startsWith("skipped ") || line.startsWith("stopped "))
                .toList();
    }

    private record SettledCheck(CommandInjectionCheck check, SettlingLateIssues late) {

        List<AuditIssue> audit(HttpRequestResponse base, AuditInsertionPoint point, Http http) {
            List<AuditIssue> issues = new java.util.ArrayList<>(check.audit(base, point, http));
            issues.addAll(late.settle(check));
            return issues;
        }

        ConsolidationAction consolidate(AuditIssue existing, AuditIssue candidate) {
            return check.consolidate(existing, candidate);
        }
    }
}
