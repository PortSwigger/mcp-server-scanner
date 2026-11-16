package com.mcpscanner.access;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

public final class IdentityRequests {

    private final Supplier<PrincipalRoster> roster;
    private final IdentityBinding binding;

    public IdentityRequests(Supplier<PrincipalRoster> roster) {
        this(roster, IdentityBinding.ROUTED);
    }

    public IdentityRequests(Supplier<PrincipalRoster> roster, IdentityBinding binding) {
        this.roster = roster;
        this.binding = binding;
    }

    public HttpRequest routed(Principal principal, HttpRequest primaryRequest) {
        return Principal.PRIMARY_ID.equals(principal.id()) ? primaryRequest : as(principal, primaryRequest);
    }

    public HttpRequest as(Principal principal, HttpRequest ownerRequest) {
        return binding.bind(principal,
                HeaderMutation.apply(ownerRequest, replacedHeaders(), principal.credentialHeaders().get()));
    }

    private Set<String> replacedHeaders() {
        Set<String> names = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        names.add(McpHeaders.SESSION_ID);
        names.add(ScannerSentinels.IDENTITY_HEADER);
        roster.get().all().forEach(principal -> names.addAll(principal.credentialHeaders().get().keySet()));
        return names;
    }
}
