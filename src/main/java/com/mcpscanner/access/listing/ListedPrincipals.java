package com.mcpscanner.access.listing;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

public record ListedPrincipals(Supplier<PrincipalRoster> roster, Supplier<List<Principal>> synthetic,
                               Supplier<Map<String, DiscoveryOutcome>> outcomes) {

    ToolListings snapshot() {
        Map<String, DiscoveryOutcome> discovered = outcomes.get();
        return new ToolListings(listed(roster.get().all(), discovered), listed(synthetic.get(), discovered));
    }

    private static List<ToolList> listed(List<Principal> principals, Map<String, DiscoveryOutcome> discovered) {
        return principals.stream()
                .flatMap(principal -> toolNames(discovered.get(principal.id()))
                        .map(tools -> new ToolList(principal, tools)).stream())
                .toList();
    }

    private static Optional<Set<String>> toolNames(DiscoveryOutcome outcome) {
        return outcome instanceof DiscoveryOutcome.Listed listed
                ? Optional.of(listed.listing().toolNames()) : Optional.empty();
    }
}
