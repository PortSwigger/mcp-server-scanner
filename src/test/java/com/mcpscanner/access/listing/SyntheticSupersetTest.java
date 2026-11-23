package com.mcpscanner.access.listing;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static com.mcpscanner.access.AccessFixtures.BOB;
import static com.mcpscanner.access.listing.ListingFixtures.FAKE_TOKEN;
import static com.mcpscanner.access.listing.ListingFixtures.NO_CREDENTIAL;
import static com.mcpscanner.access.listing.ListingFixtures.PRIMARY;
import static com.mcpscanner.access.listing.ListingFixtures.log;
import static com.mcpscanner.access.listing.ListingFixtures.substantiveCall;
import static com.mcpscanner.access.listing.ListingFixtures.tools;
import static org.assertj.core.api.Assertions.assertThat;

class SyntheticSupersetTest {

    private final SyntheticSuperset rule = new SyntheticSuperset(new SubstantiveCalls(log()));

    @Test
    void noCredentialListingAStrictSupersetOfARealUserIsMediumAndFirm() {
        List<ListingFinding> findings = rule.find(new ToolListings(
                List.of(tools(PRIMARY, "whoami", "admin"), tools(BOB, "whoami")),
                List.of(tools(NO_CREDENTIAL, "whoami", "export"))), Set.of());

        assertThat(findings).singleElement().satisfies(found -> {
            assertThat(found.kind()).isEqualTo(ListingIssueKind.SYNTHETIC_SUPERSET);
            assertThat(found.synthetic().principal()).isEqualTo(NO_CREDENTIAL);
            assertThat(found.exceeded()).extracting(ToolList::principal).containsExactly(BOB);
            assertThat(found.extraTools()).containsExactly("export");
            assertThat(found.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(found.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        });
    }

    @Test
    void aSubstantiveCallOfAnExtraToolMakesItHighAndCertain() {
        List<ListingFinding> findings = new SyntheticSuperset(new SubstantiveCalls(log(
                substantiveCall(NO_CREDENTIAL, "export")))).find(new ToolListings(
                List.of(tools(BOB, "whoami")), List.of(tools(NO_CREDENTIAL, "whoami", "export"))), Set.of());

        assertThat(findings).singleElement().satisfies(found -> {
            assertThat(found.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(found.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
        });
    }

    @Test
    void oneFindingPerSyntheticPrincipalNamesEveryRealUserItExceeds() {
        List<ListingFinding> findings = rule.find(new ToolListings(
                List.of(tools(PRIMARY, "whoami"), tools(BOB, "search")),
                List.of(tools(FAKE_TOKEN, "whoami", "search", "list_users"))), Set.of());

        assertThat(findings).singleElement().satisfies(found -> {
            assertThat(found.exceeded()).extracting(ToolList::principal).containsExactly(PRIMARY, BOB);
            assertThat(found.extraTools()).containsExactly("list_users");
        });
    }

    @Test
    void theFakeTokenAgainstThePrimaryIsLeftToTheFakeTokenFinding() {
        List<ListingFinding> findings = rule.find(new ToolListings(
                List.of(tools(PRIMARY, "whoami"), tools(BOB, "search")),
                List.of(tools(FAKE_TOKEN, "whoami", "search", "list_users"))), Set.of("list_users"));

        assertThat(findings).singleElement().satisfies(found ->
                assertThat(found.exceeded()).extracting(ToolList::principal).containsExactly(BOB));
    }

    @Test
    void aComparedUserWhoseGapIsAlreadyReportedAgainstThePrimaryRaisesNoSecondIssue() {
        List<ListingFinding> findings = rule.find(new ToolListings(
                List.of(tools(PRIMARY, "whoami"), tools(BOB, "whoami", "search")),
                List.of(tools(FAKE_TOKEN, "whoami", "search", "list_users"))), Set.of("search", "list_users"));

        assertThat(findings).isEmpty();
    }

    @Test
    void equalListsAndPartialOverlapsRaiseNothing() {
        assertThat(rule.find(new ToolListings(List.of(tools(PRIMARY, "whoami", "search")),
                List.of(tools(NO_CREDENTIAL, "whoami", "search"), tools(FAKE_TOKEN, "whoami", "export"))), Set.of()))
                .isEmpty();
    }

    @Test
    void aRealUserListingNothingIsNotExceeded() {
        assertThat(rule.find(new ToolListings(List.of(tools(BOB)), List.of(tools(NO_CREDENTIAL, "whoami"))), Set.of()))
                .isEmpty();
    }

    @Test
    void aFakeTokenListingNothingBeyondNoCredentialIsLeftToTheNoCredentialFinding() {
        List<ListingFinding> findings = rule.find(new ToolListings(List.of(tools(BOB, "whoami")),
                List.of(tools(NO_CREDENTIAL, "whoami", "export"), tools(FAKE_TOKEN, "whoami", "export"))), Set.of());

        assertThat(findings).extracting(found -> found.synthetic().principal()).containsExactly(NO_CREDENTIAL);
    }

    @Test
    void unlistedSyntheticPrincipalsRaiseNothing() {
        assertThat(rule.find(new ToolListings(List.of(tools(BOB, "whoami")), List.of()), Set.of())).isEmpty();
    }
}
