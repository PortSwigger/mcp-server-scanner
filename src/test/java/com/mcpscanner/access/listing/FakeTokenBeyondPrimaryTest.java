package com.mcpscanner.access.listing;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static com.mcpscanner.access.listing.ListingFixtures.FAKE_TOKEN;
import static com.mcpscanner.access.listing.ListingFixtures.NO_CREDENTIAL;
import static com.mcpscanner.access.listing.ListingFixtures.PRIMARY;
import static com.mcpscanner.access.listing.ListingFixtures.emptyCall;
import static com.mcpscanner.access.listing.ListingFixtures.log;
import static com.mcpscanner.access.listing.ListingFixtures.refusedCall;
import static com.mcpscanner.access.listing.ListingFixtures.substantiveCall;
import static com.mcpscanner.access.listing.ListingFixtures.tools;
import static org.assertj.core.api.Assertions.assertThat;

class FakeTokenBeyondPrimaryTest {

    @Test
    void aFakeTokenListingToolsThePrimaryDoesNotIsHighAndFirm() {
        Optional<ListingFinding> finding = new FakeTokenBeyondPrimary(new SubstantiveCalls(log())).find(
                new ToolListings(List.of(tools(PRIMARY, "whoami")),
                        List.of(tools(FAKE_TOKEN, "whoami", "list_users", "delete_user"))));

        assertThat(finding).hasValueSatisfying(found -> {
            assertThat(found.kind()).isEqualTo(ListingIssueKind.FAKE_TOKEN_BEYOND_PRIMARY);
            assertThat(found.extraTools()).containsExactly("delete_user", "list_users");
            assertThat(found.exceeded()).extracting(ToolList::principal).containsExactly(PRIMARY);
            assertThat(found.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(found.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        });
    }

    @Test
    void aSubstantiveFakeTokenCallOfAnExtraToolMakesItCertain() {
        Optional<ListingFinding> finding = new FakeTokenBeyondPrimary(new SubstantiveCalls(log(
                substantiveCall(FAKE_TOKEN, "list_users"), refusedCall(FAKE_TOKEN, "delete_user"),
                substantiveCall(FAKE_TOKEN, "whoami")))).find(
                new ToolListings(List.of(tools(PRIMARY, "whoami")),
                        List.of(tools(FAKE_TOKEN, "whoami", "list_users", "delete_user"))));

        assertThat(finding).hasValueSatisfying(found -> {
            assertThat(found.confirmations()).extracting(call -> call.item().name()).containsExactly("list_users");
            assertThat(found.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(found.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
        });
    }

    @Test
    void anEmptySuccessDoesNotConfirm() {
        Optional<ListingFinding> finding = new FakeTokenBeyondPrimary(new SubstantiveCalls(log(
                emptyCall(FAKE_TOKEN, "list_users")))).find(
                new ToolListings(List.of(tools(PRIMARY, "whoami")), List.of(tools(FAKE_TOKEN, "list_users"))));

        assertThat(finding).map(ListingFinding::confidence).contains(AuditIssueConfidence.FIRM);
    }

    @Test
    void aFakeTokenListingNoMoreThanThePrimaryRaisesNothing() {
        assertThat(new FakeTokenBeyondPrimary(new SubstantiveCalls(log())).find(new ToolListings(
                List.of(tools(PRIMARY, "whoami", "list_users")), List.of(tools(FAKE_TOKEN, "whoami")))))
                .isEmpty();
    }

    @Test
    void aRejectedFakeTokenHasNoListingAndRaisesNothing() {
        assertThat(new FakeTokenBeyondPrimary(new SubstantiveCalls(log())).find(new ToolListings(
                List.of(tools(PRIMARY, "whoami")), List.of()))).isEmpty();
    }

    @Test
    void toolsThatNoCredentialAlsoListsAreNotEscalation() {
        assertThat(new FakeTokenBeyondPrimary(new SubstantiveCalls(log())).find(new ToolListings(
                List.of(tools(PRIMARY, "whoami")),
                List.of(tools(NO_CREDENTIAL, "sign_up"), tools(FAKE_TOKEN, "sign_up"))))).isEmpty();
    }
}
