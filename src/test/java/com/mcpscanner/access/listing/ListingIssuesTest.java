package com.mcpscanner.access.listing;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.access.SyntheticCall;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.IdentityIssue;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.mcpscanner.access.AccessFixtures.BOB;
import static com.mcpscanner.access.listing.ListingFixtures.FAKE_TOKEN;
import static com.mcpscanner.access.listing.ListingFixtures.NO_CREDENTIAL;
import static com.mcpscanner.access.listing.ListingFixtures.PRIMARY;
import static com.mcpscanner.access.listing.ListingFixtures.tools;
import static org.assertj.core.api.Assertions.assertThat;

class ListingIssuesTest {

    private static final String ENDPOINT = "https://mcp.test/mcp";

    private HttpRequestResponse primaryList;
    private HttpRequestResponse fakeList;
    private HttpRequestResponse bobList;
    private HttpRequestResponse noCredentialList;
    private ListingIssues issues;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        primaryList = toolsList("Bearer alice-token", "whoami");
        fakeList = toolsList("Bearer invalid_abc123", "whoami, list_users, delete_user");
        bobList = toolsList("Bearer bob-token", "whoami");
        noCredentialList = toolsList(null, "whoami, export");
        Map<String, HttpRequestResponse> lists = Map.of(Principal.PRIMARY_ID, primaryList,
                Principal.FAKE_TOKEN_ID, fakeList, BOB.id(), bobList, Principal.ANONYMOUS_ID, noCredentialList);
        issues = new ListingIssues(new ListingEvidence(id -> Optional.ofNullable(lists.get(id)).stream().toList()), ENDPOINT);
    }

    @Test
    void anUnconfirmedFakeTokenFindingIsHighAndFirmWithBothListingsAsEvidence() {
        AuditIssue issue = issues.render(fakeTokenFinding(List.of()));

        assertThat(issue.name()).isEqualTo("MCP fake token lists tools the primary user does not list");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.baseUrl()).isEqualTo(ENDPOINT);
        assertThat(issue.detail()).contains("delete_user, list_users").contains("Primary");
        assertThat(issue.remediation()).contains("unknown").contains("service");
        assertThat(issue.requestResponses()).hasSize(2);
        assertThat(issue.requestResponses().get(1).request().headerValue("Authorization"))
                .isEqualTo("Bearer invalid_abc123");
    }

    @Test
    void thePrimaryCredentialStaysRawInItsListingEvidence() {
        AuditIssue issue = issues.render(fakeTokenFinding(List.of()));

        assertThat(issue.requestResponses().get(0).request().headerValue("Authorization"))
                .isEqualTo("Bearer alice-token");
        assertThat(issue.requestResponses().get(0).response().bodyToString()).contains("whoami");
    }

    @Test
    void aPrimaryCredentialInACustomHeaderStaysRawInItsListingEvidence() {
        HttpRequestResponse apiKeyList = HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post(ENDPOINT, Map.of("X-API-Key", "alice-api-key"), "{\"method\":\"tools/list\"}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{\"tools\":\"whoami\"}"));
        Map<String, HttpRequestResponse> lists = Map.of(Principal.PRIMARY_ID, apiKeyList, Principal.FAKE_TOKEN_ID, fakeList);
        ListingIssues apiKeyIssues = new ListingIssues(new ListingEvidence(id -> Optional.ofNullable(lists.get(id)).stream().toList()), ENDPOINT);

        AuditIssue issue = apiKeyIssues.render(fakeTokenFinding(List.of()));

        assertThat(issue.requestResponses().get(0).request().headerValue("X-API-Key"))
                .isEqualTo("alice-api-key");
    }

    @Test
    void aConfirmedFakeTokenFindingIsCertainAndAttachesTheSuccessfulCall() {
        HttpRequestResponse call = HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post(ENDPOINT, Map.of("Authorization", "Bearer invalid_abc123"),
                        "{\"method\":\"tools/call\"}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{\"result\":\"users: alice, bob\"}"));
        AuditIssue issue = issues.render(fakeTokenFinding(
                List.of(ListingFixtures.substantiveCall(FAKE_TOKEN, "list_users", call))));

        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
        assertThat(issue.detail()).contains("list_users").contains("returned");
        assertThat(issue.requestResponses()).hasSize(3);
        assertThat(issue.requestResponses().get(2).response().bodyToString()).contains("users: alice, bob");
    }

    @Test
    void aLaterConfirmedFakeTokenFindingReplacesTheFirmOneAlreadyFiled() {
        HttpRequestResponse call = HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post(ENDPOINT, Map.of("Authorization", "Bearer invalid_abc123"),
                        "{\"method\":\"tools/call\"}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{\"result\":\"users: alice, bob\"}"));
        AuditIssue firm = issues.render(fakeTokenFinding(List.of()));
        AuditIssue certain = issues.render(fakeTokenFinding(
                List.of(ListingFixtures.substantiveCall(FAKE_TOKEN, "list_users", call))));

        assertThat(IdentityIssue.consolidate(firm, certain)).isEqualTo(ConsolidationAction.KEEP_NEW);
        assertThat(IdentityIssue.consolidate(certain, firm)).isEqualTo(ConsolidationAction.KEEP_EXISTING);
    }

    @Test
    void aSupersetFindingNamesTheSyntheticPrincipalAndTheUsersItExceeds() {
        AuditIssue issue = issues.render(new ListingFinding(ListingIssueKind.SYNTHETIC_SUPERSET,
                tools(NO_CREDENTIAL, "whoami", "export"), List.of(tools(BOB, "whoami")), Set.of("export"),
                List.of()));

        assertThat(issue.name()).isEqualTo("MCP unauthenticated principal lists more tools than a real user");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("No credential").contains("bob").contains("export");
        assertThat(issue.requestResponses()).hasSize(2);
        assertThat(issue.requestResponses().get(0).request().headerValue("Authorization"))
                .isEqualTo("Bearer bob-token");
    }

    @Test
    void aNoCredentialFindingNamesThePrincipalByItsUserFacingLabel() {
        AuditIssue issue = issues.render(new ListingFinding(ListingIssueKind.SYNTHETIC_SUPERSET,
                tools(NO_CREDENTIAL, "whoami", "export"), List.of(tools(BOB, "whoami")), Set.of("export"),
                List.of()));

        assertThat(issue.detail()).contains("No credential (no credentials sent) lists")
                .contains("as No credential").doesNotContain("Anonymous");
    }

    @Test
    void aFakeTokenFindingNamesThePrincipalAsTheAccessColumnDoes() {
        AuditIssue issue = issues.render(fakeTokenFinding(List.of()));

        assertThat(issue.detail()).contains("Fake token (an invalid token the server never issued) lists")
                .contains("as Fake token");
    }

    private static ListingFinding fakeTokenFinding(List<SyntheticCall> confirmations) {
        return new ListingFinding(ListingIssueKind.FAKE_TOKEN_BEYOND_PRIMARY,
                tools(FAKE_TOKEN, "whoami", "list_users", "delete_user"), List.of(tools(PRIMARY, "whoami")),
                Set.of("list_users", "delete_user"), confirmations);
    }

    private static HttpRequestResponse toolsList(String authorization, String tools) {
        Map<String, String> headers = authorization == null ? Map.of() : Map.of("Authorization", authorization);
        return HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post(ENDPOINT, headers, "{\"method\":\"tools/list\"}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"tools\":\""
                        + tools + "\"}"));
    }
}
