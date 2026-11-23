package com.mcpscanner.access.listing;

import com.mcpscanner.checks.api.Principal;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;

final class SyntheticSuperset {

    private final SubstantiveCalls calls;

    SyntheticSuperset(SubstantiveCalls calls) {
        this.calls = calls;
    }

    List<ListingFinding> find(ToolListings listings, Set<String> reportedFakeTokenTools) {
        return listings.synthetic().stream()
                .filter(synthetic -> addsToNoCredential(synthetic, listings))
                .flatMap(synthetic -> finding(synthetic, exceeded(synthetic, listings, reportedFakeTokenTools))
                        .stream())
                .toList();
    }

    private Optional<ListingFinding> finding(ToolList synthetic, List<ToolList> exceeded) {
        if (exceeded.isEmpty()) {
            return Optional.empty();
        }
        SortedSet<String> extra = synthetic.beyond(exceeded.stream().flatMap(user -> user.tools().stream()).toList());
        return Optional.of(new ListingFinding(ListingIssueKind.SYNTHETIC_SUPERSET, synthetic, exceeded, extra,
                calls.of(synthetic.principal(), extra)));
    }

    private static List<ToolList> exceeded(ToolList synthetic, ToolListings listings,
                                           Set<String> reportedFakeTokenTools) {
        return listings.realUsers().stream()
                .filter(synthetic::strictlyExceeds)
                .filter(user -> !alreadyReported(synthetic, user, reportedFakeTokenTools))
                .toList();
    }

    private static boolean alreadyReported(ToolList synthetic, ToolList user, Set<String> reportedFakeTokenTools) {
        return Principal.FAKE_TOKEN_ID.equals(synthetic.id()) && !reportedFakeTokenTools.isEmpty()
                && (Principal.PRIMARY_ID.equals(user.id())
                || reportedFakeTokenTools.containsAll(synthetic.beyond(user.tools())));
    }

    private static boolean addsToNoCredential(ToolList synthetic, ToolListings listings) {
        return Principal.isAnonymous(synthetic.id()) || listings.listed(Principal.ANONYMOUS_ID)
                .filter(synthetic::within).isEmpty();
    }
}
