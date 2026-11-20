package com.mcpscanner.access.listing;

import com.mcpscanner.checks.api.Principal;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;

final class FakeTokenBeyondPrimary {

    private final SubstantiveCalls calls;

    FakeTokenBeyondPrimary(SubstantiveCalls calls) {
        this.calls = calls;
    }

    Optional<ListingFinding> find(ToolListings listings) {
        return listings.listed(Principal.FAKE_TOKEN_ID).flatMap(fake -> listings.listed(Principal.PRIMARY_ID)
                .flatMap(primary -> beyond(fake, primary, noCredentialTools(listings))));
    }

    private Optional<ListingFinding> beyond(ToolList fake, ToolList primary, Set<String> noCredentialTools) {
        SortedSet<String> extra = fake.beyond(primary.tools());
        extra.removeAll(noCredentialTools);
        return extra.isEmpty() ? Optional.empty() : Optional.of(new ListingFinding(
                ListingIssueKind.FAKE_TOKEN_BEYOND_PRIMARY, fake, List.of(primary), extra,
                calls.of(fake.principal(), extra)));
    }

    private static Set<String> noCredentialTools(ToolListings listings) {
        return listings.listed(Principal.ANONYMOUS_ID).map(ToolList::tools).map(Set::copyOf).orElse(Set.of());
    }
}
