package com.mcpscanner.access.listing;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.access.ListingAudit;
import com.mcpscanner.access.SyntheticCallLog;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

public final class ToolListingAudit implements ListingAudit {

    private final ListedPrincipals principals;
    private final SubstantiveCalls calls;
    private final Function<String, List<HttpRequestResponse>> toolsLists;
    private final Supplier<String> endpoint;

    public ToolListingAudit(ListedPrincipals principals, SyntheticCallLog calls,
                            Function<String, List<HttpRequestResponse>> toolsLists, Supplier<String> endpoint) {
        this.principals = principals;
        this.calls = new SubstantiveCalls(calls);
        this.toolsLists = toolsLists;
        this.endpoint = endpoint;
    }

    @Override
    public List<AuditIssue> issues() {
        ToolListings listings = principals.snapshot();
        Optional<ListingFinding> fakeToken = new FakeTokenBeyondPrimary(calls).find(listings);
        List<ListingFinding> supersets = new SyntheticSuperset(calls).find(listings,
                fakeToken.map(ListingFinding::extraTools).orElse(Set.of()));
        List<ListingFinding> findings = Stream.concat(fakeToken.stream(), supersets.stream()).toList();
        if (findings.isEmpty()) {
            return List.of();
        }
        ListingIssues issues = new ListingIssues(new ListingEvidence(toolsLists), endpoint.get());
        return findings.stream().map(issues::render).toList();
    }
}
