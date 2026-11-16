package com.mcpscanner.ui;

import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.credentials.ScopeApprovals;
import com.mcpscanner.core.oauth.AuthorizationApproval;
import com.mcpscanner.ui.widgets.DialogOwner;

import java.awt.Component;
import java.net.URI;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

final class SwingScopeApprovals implements ScopeApprovals {

    private final DialogOwner owner;
    private final Component parent;
    private final Consumer<String> declineLog;

    SwingScopeApprovals(DialogOwner owner, Component parent, Consumer<String> declineLog) {
        this.owner = owner;
        this.parent = parent;
        this.declineLog = declineLog;
    }

    @Override
    public Function<Set<String>, AuthorizationApproval> forIdentity(Identity identity, URI issuer, URI resource,
                                                                    String clientId) {
        return new OAuthScopeApproval(owner, parent, issuer, resource, clientId, declineLog)::approve;
    }
}
