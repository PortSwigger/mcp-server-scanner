package com.mcpscanner.identity.credentials;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthException;
import com.mcpscanner.auth.oauth.OAuthSession;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.time.Clock;
import java.util.Objects;
import java.util.function.Supplier;

public final class OAuthIdentitySignIn implements IdentitySignIn {

    static final String NO_ISSUER_OR_ENDPOINT = "Enter an Issuer, or an Endpoint to discover the issuer from";

    private final OAuthAuthorizationFlow flow;
    private final Supplier<URI> mcpResource;
    private final IssuerDiscovery issuerDiscovery;
    private final ScopeApprovals scopeApprovals;
    private final Clock clock;
    private final McpEventLog eventLog;
    private final Runnable signInAttemptStart;

    public OAuthIdentitySignIn(OAuthAuthorizationFlow flow, Supplier<URI> mcpResource, IssuerDiscovery issuerDiscovery,
                               ScopeApprovals scopeApprovals, Clock clock, McpEventLog eventLog) {
        this(flow, mcpResource, issuerDiscovery, scopeApprovals, clock, eventLog, () -> { });
    }

    public OAuthIdentitySignIn(OAuthAuthorizationFlow flow, Supplier<URI> mcpResource, IssuerDiscovery issuerDiscovery,
                               ScopeApprovals scopeApprovals, Clock clock, McpEventLog eventLog,
                               Runnable signInAttemptStart) {
        this.signInAttemptStart = Objects.requireNonNull(signInAttemptStart, "signInAttemptStart");
        this.flow = Objects.requireNonNull(flow, "flow");
        this.mcpResource = Objects.requireNonNull(mcpResource, "mcpResource");
        this.issuerDiscovery = Objects.requireNonNull(issuerDiscovery, "issuerDiscovery");
        this.scopeApprovals = Objects.requireNonNull(scopeApprovals, "scopeApprovals");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog");
    }

    @Override
    public AuthStrategy signIn(Identity identity, OAuthClientHints hints) {
        signInAttemptStart.run();
        URI resource = mcpResource.get();
        eventLog.info("Signing in identity \"" + identity.name() + "\" through the browser");
        return hints.issuer() != null ? signIn(identity, resource, hints, flow.connect(resource, hints))
                : signInDiscoveringIssuer(identity, resource, hints);
    }

    private AuthStrategy signInDiscoveringIssuer(Identity identity, URI resource, OAuthClientHints hints) {
        if (resource.getHost() == null) {
            throw new OAuthException(NO_ISSUER_OR_ENDPOINT);
        }
        DiscoveredMetadata discovered = issuerDiscovery.discover(resource);
        OAuthClientHints withIssuer = hints.withIssuer(discovered.issuer(), discovered.selectedScopes());
        return signIn(identity, resource, withIssuer, flow.connect(resource, withIssuer, discovered.asMetadata()));
    }

    private AuthStrategy signIn(Identity identity, URI resource, OAuthClientHints hints, OAuthSession session) {
        return new OAuthAuthCodeStrategy(hints.issuer(), session.clientId(), session.sharedSession(), clock, eventLog,
                scopeApprovals.forIdentity(identity, hints.issuer(), resource, session.clientId()),
                session.registrationMode());
    }
}
