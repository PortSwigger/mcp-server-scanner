package com.mcpscanner.access.listing;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.access.SyntheticCallLog;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.mcpscanner.access.AccessFixtures.BOB;
import static com.mcpscanner.access.AccessFixtures.listing;
import static com.mcpscanner.access.AccessFixtures.readOnlyTool;
import static com.mcpscanner.access.listing.ListingFixtures.FAKE_TOKEN;
import static com.mcpscanner.access.listing.ListingFixtures.NO_CREDENTIAL;
import static com.mcpscanner.access.listing.ListingFixtures.PRIMARY;
import static com.mcpscanner.access.listing.ListingFixtures.log;
import static com.mcpscanner.access.listing.ListingFixtures.substantiveCall;
import static org.assertj.core.api.Assertions.assertThat;

class ToolListingAuditTest {

    private final Map<String, DiscoveryOutcome> outcomes = new HashMap<>();
    private PrincipalRoster roster = PrincipalRoster.of(PRIMARY, List.of());

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void aServerMappingAnUnknownTokenToAServiceAccountRaisesTheFakeTokenIssueOnce() {
        lists(PRIMARY, "whoami");
        lists(FAKE_TOKEN, "whoami", "list_users", "delete_user");
        refuses(NO_CREDENTIAL);

        List<AuditIssue> issues = audit(log(substantiveCall(FAKE_TOKEN, "list_users", fakeTokenCall()))).issues();

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP fake token lists tools the primary user does not list");
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
        });
    }

    @Test
    void aServerRejectingUnknownAndAbsentTokensRaisesNothing() {
        lists(PRIMARY, "whoami");
        refuses(FAKE_TOKEN);
        refuses(NO_CREDENTIAL);

        assertThat(audit(log()).issues()).isEmpty();
    }

    @Test
    void twoRealUsersListingDifferentToolsRaiseNothing() {
        roster = PrincipalRoster.of(PRIMARY, List.of(BOB));
        lists(PRIMARY, "whoami", "admin_report");
        lists(BOB, "whoami");
        refuses(FAKE_TOKEN);
        refuses(NO_CREDENTIAL);

        assertThat(audit(log()).issues()).isEmpty();
    }

    @Test
    void noCredentialListingMoreThanAComparedUserRaisesTheSupersetIssue() {
        roster = PrincipalRoster.of(PRIMARY, List.of(BOB));
        lists(PRIMARY, "whoami", "export");
        lists(BOB, "whoami");
        lists(NO_CREDENTIAL, "whoami", "export");
        refuses(FAKE_TOKEN);

        assertThat(audit(log()).issues()).extracting(AuditIssue::name)
                .containsExactly("MCP unauthenticated principal lists more tools than a real user");
    }

    @Test
    void syntheticPrincipalsStillBeingListedRaiseNothing() {
        lists(PRIMARY, "whoami");
        outcomes.put(FAKE_TOKEN.id(), DiscoveryOutcome.Discovering.INSTANCE);

        assertThat(audit(log()).issues()).isEmpty();
    }

    private ToolListingAudit audit(SyntheticCallLog calls) {
        return new ToolListingAudit(new ListedPrincipals(() -> roster, () -> List.of(NO_CREDENTIAL, FAKE_TOKEN),
                () -> Map.copyOf(outcomes)), calls, id -> List.<HttpRequestResponse>of(),
                () -> "https://mcp.test/mcp");
    }

    private void lists(Principal principal, String... tools) {
        outcomes.put(principal.id(), new DiscoveryOutcome.Listed(listing(
                Arrays.stream(tools).map(name -> readOnlyTool(name)).toList(), List.of())));
    }

    private static HttpRequestResponse fakeTokenCall() {
        return HttpRequestResponse.httpRequestResponse(ImmutableHttpRequest.post("https://mcp.test/mcp",
                        Map.of("Authorization", "Bearer invalid_abc123"), "{\"method\":\"tools/call\"}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{\"result\":{}}"));
    }

    private void refuses(Principal principal) {
        outcomes.put(principal.id(), new DiscoveryOutcome.Failed("HTTP 401"));
    }
}
