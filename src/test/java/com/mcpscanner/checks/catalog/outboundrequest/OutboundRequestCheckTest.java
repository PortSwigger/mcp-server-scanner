package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.shared.collaborator.FakeCollaborator;
import com.mcpscanner.checks.shared.collaborator.TaggingCopies;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.JsonParameterInsertionPoint;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static com.mcpscanner.checks.catalog.outboundrequest.FetchingTarget.bodyContains;
import static com.mcpscanner.checks.catalog.outboundrequest.FetchingTarget.headerCarriesPayload;
import static com.mcpscanner.checks.catalog.outboundrequest.OutboundFixtures.exchange;
import static com.mcpscanner.checks.catalog.outboundrequest.OutboundFixtures.field;
import static com.mcpscanner.checks.catalog.outboundrequest.OutboundFixtures.mcpRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OutboundRequestCheckTest {

    private static final int FORMS_FOR_A_NON_URL_VALUE = 5;

    private static final String URL_FIELD = "MCP field: params.arguments.url";
    private static final String PROGRESS_TOKEN = "MCP field: params._meta.progressToken";

    private final FakeCollaborator collaborator = new FakeCollaborator();
    private final FetchingTarget target = new FetchingTarget(collaborator);
    private SettledOutboundCheck check;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        check = checkWith(Optional.of(collaborator));
    }

    @Test
    void reportsAnHttpRequestToThePayloadHostAsAMediumFirmOutboundRequest() {
        target.fetchingWhen(bodyContains("\"url\":\"http://"));
        HttpRequest toolCall = mcpRequest(OutboundFixtures.TOOL_CALL);

        List<AuditIssue> issues = audit(toolCall, URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP server outbound request");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).startsWith("<p>Field: MCP field: params.arguments.url in tools/call "
                    + "render_report</p>").contains("HTTP request").contains("absolute URL");
            assertThat(issue.requestResponses()).hasSize(1);
        });
    }

    @Test
    void reportsAServerThatOnlyConnectsForAFlagShapedValueAndNamesTheFlag() {
        target.fetchingWhen(bodyContains("\"url\":\"--server=http://"));

        List<AuditIssue> issues = audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.detail()).contains("long flag --server --server=http://");
            assertThat(issue.requestResponses()).hasSize(1);
        });
    }

    @Test
    void reportsAnAttachedShortFlagCarryingTheHostAsOneProbe() {
        target.fetchingWhen(bodyContains("\"url\":\"-shttp://"));

        List<AuditIssue> issues = audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue ->
                assertThat(issue.detail()).contains("attached short flag -s -shttp://"));
    }

    @Test
    void reportsALookupWithoutARequestAsLowTentative() {
        target.fetchingWhen(bodyContains(FakeCollaborator.DOMAIN)).resolvingOnly();

        List<AuditIssue> issues = audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("DNS").contains("validator");
            assertThat(issue.requestResponses()).hasSize(ProbeForm.values().length);
        });
    }

    @Test
    void ratesAForwardedCredentialHighAndNamesTheHeader() {
        target.fetchingWhen(bodyContains(FakeCollaborator.DOMAIN)).forwarding(Map.of("Authorization", "Bearer t"));

        List<AuditIssue> issues = audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.detail()).contains("Authorization");
        });
    }

    @Test
    void keepsTheBaseAndEveryProbeAsTheWatchsTemporaryFileCopies() {
        target.fetchingWhen(bodyContains(FakeCollaborator.DOMAIN)).resolvingOnly();
        TaggingCopies copies = new TaggingCopies();
        HttpRequest toolCall = mcpRequest(OutboundFixtures.TOOL_CALL);

        List<AuditIssue> issues = SettledOutboundCheck.keepingIn(copies, Optional.of(collaborator))
                .audit(exchange(toolCall), field(toolCall, URL_FIELD), target.http());

        assertThat(copies.keptCount()).isEqualTo(1 + ProbeForm.values().length);
        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.requestResponses()).hasSize(ProbeForm.values().length).allMatch(TaggingCopies::wasKept);
            assertThat(issue.baseUrl()).isEqualTo(toolCall.url());
        });
    }

    @Test
    void reportsAFetchToolRequestingItsUrlAsAnOutboundRequestByDesign() {
        target.fetchingWhen(bodyContains("\"url\":\"http://"));

        List<AuditIssue> issues = audit(mcpRequest(OutboundFixtures.FETCH_TOOL_CALL), URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP server outbound request by design");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.definition().background()).doesNotContain("did not intend");
        });
    }

    @Test
    void reportsAFetchPromptRequestingItsUrlAsAnOutboundRequestByDesign() {
        target.fetchingWhen(bodyContains("\"url\":\"http://"));

        List<AuditIssue> issues = audit(mcpRequest(OutboundFixtures.FETCH_PROMPT_GET), URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP server outbound request by design");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        });
    }

    @Test
    void reportsAFetchToolThatForwardsCredentialsAsAHighOutboundRequest() {
        target.fetchingWhen(bodyContains(FakeCollaborator.DOMAIN)).forwarding(Map.of("Authorization", "Bearer t"));

        List<AuditIssue> issues = audit(mcpRequest(OutboundFixtures.FETCH_TOOL_CALL), URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP server outbound request");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        });
    }

    @Test
    void sendsEveryProbeFormEachWithItsOwnPayload() {
        audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD);

        String host = "p\\d+x\\." + FakeCollaborator.DOMAIN.replace(".", "\\.");
        List<String> bodies = target.received().stream().map(HttpRequest::bodyToString).toList();
        assertThat(bodies).hasSize(7);
        assertThat(bodies.get(0)).containsPattern("\"url\":\"http://" + host + "\"");
        assertThat(bodies.get(1)).containsPattern("\"url\":\"" + host + "\"");
        assertThat(bodies.get(4)).containsPattern("\"url\":\"--server=http://" + host + "/\"");
        assertThat(bodies.get(5)).containsPattern("\"url\":\"--url=http://" + host + "/\"");
        assertThat(bodies.get(6)).containsPattern("\"url\":\"-shttp://" + host + "/\"");
        assertThat(bodies.stream().map(body -> body.replaceAll("[^0-9]", "")).distinct()).hasSize(7);
    }

    @Test
    void keepsTheOriginalHostAndPointsItAtThePayloadHostForAUrlValue() {
        audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD);

        List<String> bodies = target.received().stream().map(HttpRequest::bodyToString).toList();
        String domain = FakeCollaborator.DOMAIN.replace(".", "\\.");
        assertThat(bodies).anyMatch(body -> body.matches(
                ".*\"url\":\"https://docs\\.example\\.test\\.p\\d+x\\." + domain + "/a\".*"));
        assertThat(bodies).anyMatch(body -> body.matches(
                ".*\"url\":\"https://docs\\.example\\.test@p\\d+x\\." + domain + "/a\".*"));
    }

    @Test
    void sendsNoOriginPreservingFormForAValueThatIsNotAUrl() {
        audit(mcpRequest(OutboundFixtures.TOOL_CALL), "MCP field: params.arguments.limit");

        assertThat(target.received()).hasSize(FORMS_FOR_A_NON_URL_VALUE);
    }

    @Test
    void reportsAServerThatOnlyFetchesAnAllowlistedPrefixAsAnOutboundRequest() {
        target.fetchingWhen(bodyContains("\"url\":\"https://docs.example.test."));

        List<AuditIssue> issues = audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD);

        assertThat(issues).singleElement().satisfies(issue -> assertThat(issue.detail())
                .contains("original host with the payload host appended"));
    }

    @Test
    void staysSilentWhenTheServerNeverReachesThePayloadHost() {
        assertThat(audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD)).isEmpty();
    }

    @Test
    void ignoresInteractionsForPayloadsThatThisFieldDidNotSend() {
        HttpRequest toolCall = mcpRequest(OutboundFixtures.TOOL_CALL);
        target.fetchingWhen(request -> {
            collaborator.interactWithUnknownPayload("p999x");
            return false;
        });

        assertThat(audit(toolCall, "MCP field: params.arguments.limit")).isEmpty();
    }

    @Test
    void probesHeadersAndNotifications() {
        target.fetchingWhen(headerCarriesPayload("Mcp-Session-Id"));
        assertThat(audit(mcpRequest(OutboundFixtures.TOOL_CALL), "MCP header: Mcp-Session-Id")).hasSize(1);

        target.fetchingWhen(bodyContains("\"progressToken\":\"http://"));
        assertThat(audit(mcpRequest(OutboundFixtures.NOTIFICATION), "MCP field: params.progressToken"))
                .singleElement().extracting(AuditIssue::detail).asString().contains("notifications/progress");
    }

    @Test
    void reportsClientMetadataFetchesAsInformation() {
        target.fetchingWhen(bodyContains("\"websiteUrl\":\"http://"));

        assertThat(audit(mcpRequest(OutboundFixtures.INITIALIZE), "MCP field: params.clientInfo.websiteUrl"))
                .singleElement().satisfies(issue -> {
                    assertThat(issue.name()).isEqualTo("MCP client metadata URL fetched by server");
                    assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
                });
    }

    @Test
    void reportsOAuthClientMetadataFetchesAsInformation() {
        target.fetchingWhen(bodyContains("\"client_uri\":\"http://"));
        HttpRequest registration = OutboundFixtures.jsonRequest("http://as.example.test/register",
                OutboundFixtures.REGISTRATION);
        AuditInsertionPoint clientUri = new JsonParameterInsertionPoint(registration, "client_uri");

        List<AuditIssue> issues = check.audit(exchange(registration), clientUri, target.http());

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("OAuth client metadata URL fetched by authorization server");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        });
    }

    @Test
    void sendsNothingWithoutCollaborator() {
        check = checkWith(Optional.empty());
        target.fetchingWhen(bodyContains(FakeCollaborator.DOMAIN));

        assertThat(audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD)).isEmpty();
        assertThat(target.received()).isEmpty();
    }

    @Test
    void sendsNothingForFieldsItDoesNotOwn() {
        HttpRequest plain = OutboundFixtures.jsonRequest("http://app.example.test/search", OutboundFixtures.PLAIN_JSON);
        AuditInsertionPoint builtIn = mock(AuditInsertionPoint.class);
        when(builtIn.name()).thenReturn("query");
        when(builtIn.type()).thenReturn(AuditInsertionPointType.PARAM_JSON);

        assertThat(check.audit(exchange(plain), builtIn, target.http())).isEmpty();
        assertThat(target.received()).isEmpty();
    }

    @Test
    void keepsOneIssuePerFieldAndBothForDifferentFields() {
        target.fetchingWhen(bodyContains(FakeCollaborator.DOMAIN));
        HttpRequest toolCall = mcpRequest(OutboundFixtures.TOOL_CALL);
        AuditIssue first = audit(toolCall, URL_FIELD).get(0);
        AuditIssue again = checkWith(Optional.of(collaborator))
                .audit(exchange(toolCall), field(toolCall, URL_FIELD), target.http()).get(0);
        AuditIssue other = audit(toolCall, "MCP field: params.arguments.limit").get(0);

        assertThat(check.consolidate(first, again)).isEqualTo(ConsolidationAction.KEEP_EXISTING);
        assertThat(check.consolidate(lookupOnly(toolCall), first)).isEqualTo(ConsolidationAction.KEEP_NEW);
        assertThat(check.consolidate(first, lookupOnly(toolCall))).isEqualTo(ConsolidationAction.KEEP_EXISTING);
        assertThat(check.consolidate(first, other)).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    @Test
    void reportsAMetaFieldFetchedInEveryMethodOnceForTheEndpoint() {
        target.fetchingWhen(bodyContains("\"progressToken\":\"http://"));

        List<AuditIssue> issues = auditEvery(OutboundFixtures.METHODS_WITH_PROGRESS_TOKEN, PROGRESS_TOKEN);

        assertThat(issues).singleElement().satisfies(issue -> assertThat(issue.detail())
                .startsWith("<p>Field: " + PROGRESS_TOKEN + "</p><p>Confirmed in tools/list."));
        assertThat(target.received()).hasSize(FORMS_FOR_A_NON_URL_VALUE);
    }

    @Test
    void keepsProbingAFieldInOtherMethodsUntilTheServerFetchesIt() {
        target.fetchingWhen(bodyContains("\"method\":\"prompts/list\"").and(bodyContains("\"progressToken\":\"http://")));

        List<AuditIssue> issues = auditEvery(OutboundFixtures.METHODS_WITH_PROGRESS_TOKEN, PROGRESS_TOKEN);

        assertThat(issues).singleElement().extracting(AuditIssue::detail).asString().contains("prompts/list");
        assertThat(target.received()).hasSize(3 * FORMS_FOR_A_NON_URL_VALUE);
    }

    @Test
    void reportsAStrongerConfirmationOfTheSameFieldInAnotherMethod() {
        target.fetchingWhen(bodyContains("\"progressToken\":\"")).resolvingOnly();
        List<String> methods = OutboundFixtures.METHODS_WITH_PROGRESS_TOKEN;
        AuditIssue lookup = audit(mcpRequest(methods.get(0)), PROGRESS_TOKEN).get(0);
        AuditIssue repeatedLookup = audit(mcpRequest(methods.get(1)), PROGRESS_TOKEN).stream().findFirst().orElse(null);
        FetchingTarget fetching = new FetchingTarget(collaborator).fetchingWhen(bodyContains("\"progressToken\":\"http://"));
        HttpRequest third = mcpRequest(methods.get(2));
        List<AuditIssue> request = check.audit(exchange(third), field(third, PROGRESS_TOKEN), fetching.http());
        List<AuditIssue> afterRequest = audit(mcpRequest(methods.get(3)), PROGRESS_TOKEN);

        assertThat(repeatedLookup).isNull();
        assertThat(request).singleElement().satisfies(issue -> {
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(check.consolidate(lookup, issue)).isEqualTo(ConsolidationAction.KEEP_NEW);
        });
        assertThat(afterRequest).isEmpty();
    }

    @Test
    void reportsAToolArgumentSeparatelyForEachTool() {
        target.fetchingWhen(bodyContains("\"url\":\"http://"));

        List<AuditIssue> issues = auditEvery(List.of(OutboundFixtures.TOOL_CALL, OutboundFixtures.OTHER_TOOL_CALL),
                URL_FIELD);

        assertThat(issues).hasSize(2);
        assertThat(check.consolidate(issues.get(0), issues.get(1))).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    @Test
    void probesAConfirmedFieldAgainAtAnotherHostOrAfterTheConnectionEnds() {
        target.fetchingWhen(bodyContains("\"progressToken\":\"http://"));
        HttpRequest toolCall = mcpRequest(OutboundFixtures.TOOL_CALL);
        HttpRequest elsewhere = toolCall.withService(HttpService.httpService("other.example.test", 80, false));
        audit(toolCall, PROGRESS_TOKEN);

        List<AuditIssue> otherHost = audit(elsewhere, PROGRESS_TOKEN);
        check.clearConnectionState();
        List<AuditIssue> reconnected = audit(toolCall, PROGRESS_TOKEN);

        assertThat(otherHost).hasSize(1);
        assertThat(reconnected).hasSize(1);
    }

    private List<AuditIssue> auditEvery(List<String> bodies, String fieldName) {
        return bodies.stream().map(OutboundFixtures::mcpRequest)
                .flatMap(request -> audit(request, fieldName).stream()).toList();
    }

    @Test
    void neverClaimsServerSideRequestForgery() {
        target.fetchingWhen(bodyContains(FakeCollaborator.DOMAIN));
        AuditIssue issue = audit(mcpRequest(OutboundFixtures.TOOL_CALL), URL_FIELD).get(0);
        String text = String.join(" ", check.descriptor().id(), check.descriptor().displayName(),
                check.descriptor().description(), check.descriptor().issueBackground(), issue.name(), issue.detail(),
                issue.remediation(), issue.definition().background()).toLowerCase(Locale.ROOT);

        assertThat(text).doesNotContain("ssrf").doesNotContain("server-side request forgery");
    }

    private AuditIssue lookupOnly(HttpRequest toolCall) {
        FakeCollaborator resolving = new FakeCollaborator();
        FetchingTarget resolvingTarget = new FetchingTarget(resolving)
                .fetchingWhen(bodyContains(FakeCollaborator.DOMAIN)).resolvingOnly();
        return checkWith(Optional.of(resolving))
                .audit(exchange(toolCall), field(toolCall, URL_FIELD), resolvingTarget.http()).get(0);
    }

    private List<AuditIssue> audit(HttpRequest request, String fieldName) {
        return check.audit(exchange(request), field(request, fieldName), target.http());
    }

    private static SettledOutboundCheck checkWith(Optional<burp.api.montoya.collaborator.CollaboratorClient> client) {
        return SettledOutboundCheck.over(client, McpEventLog.noop());
    }
}
