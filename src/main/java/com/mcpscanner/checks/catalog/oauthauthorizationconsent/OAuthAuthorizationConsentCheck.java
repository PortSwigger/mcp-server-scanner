package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.WholeCheckTrial;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.AuthorizationServerDiscovery;
import com.mcpscanner.checks.shared.oauth.HttpUris;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.checks.shared.oauth.TokenRevocation;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestKind;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class OAuthAuthorizationConsentCheck implements HostCheck {

    private final CheckLog log;
    private final McpEventLog eventLog;
    private final Supplier<AuthStrategy> authStrategy;
    private final OAuthAuthorizationConsentIssues issues =
            new OAuthAuthorizationConsentIssues(OAuthAuthorizationConsentDescriptor.DESCRIPTOR);
    private final List<HostTrial> trials;

    public OAuthAuthorizationConsentCheck(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy) {
        this(eventLog, authStrategy, SignedInConsent.OPTED_OUT);
    }

    public OAuthAuthorizationConsentCheck(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy,
                                          SignedInConsent signedInConsent) {
        this.log = new CheckLog(eventLog, OAuthAuthorizationConsentDescriptor.DESCRIPTOR.id());
        this.eventLog = eventLog;
        this.authStrategy = authStrategy;
        this.trials = List.of(new WholeCheckTrial(this),
                new SignedInConsentTrial(this, log, eventLog, authStrategy, signedInConsent, issues));
    }

    @Override
    public CheckDescriptor descriptor() {
        return OAuthAuthorizationConsentDescriptor.DESCRIPTOR;
    }

    @Override
    public List<HostTrial> trials() {
        return trials;
    }

    @Override
    public boolean appliesTo(HttpRequestResponse hostBaseRequestResponse) {
        return hostBaseRequestResponse.request() != null
                && McpRequestDetector.classify(hostBaseRequestResponse) != McpRequestKind.NOT_MCP
                && HttpUris.parse(hostBaseRequestResponse.request().url()).isPresent();
    }

    @Override
    public String appliesOnlyTo() {
        return "MCP requests to an http(s) URL";
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse hostBaseRequestResponse, Http http) {
        OAuthHttp oauthHttp = new OAuthHttp(http);
        AuditScope scope = new AuditScope(hostBaseRequestResponse, http, oauthHttp,
                new OAuthSkipLog(log, oauthHttp), hostBaseRequestResponse.request().url());
        try {
            return audit(scope);
        } finally {
            scope.skips().stoppedIfRateLimited(scope.mcpEndpoint());
        }
    }

    private List<AuditIssue> audit(AuditScope scope) {
        Optional<AuthorizationServer> server = new AuthorizationServerDiscovery(scope.oauthHttp())
                .discover(scope.hostBase())
                .filter(discovered -> discovered.registrationEndpoint().isPresent());
        if (server.isEmpty()) {
            scope.skips().notRun(scope.mcpEndpoint(),
                    SkipReason.prerequisiteMissing("no authorization server with a registration endpoint discovered"));
            return List.of();
        }
        ProbeClientRegistrar registrar =
                new ProbeClientRegistrar(scope.oauthHttp(), server.get().registrationEndpoint().orElseThrow());
        try {
            Optional<ProbeClient> client = ProbeClient.register(registrar);
            if (client.isEmpty()) {
                scope.skips().notRun(scope.mcpEndpoint(),
                        SkipReason.prerequisiteMissing("dynamic client registration did not issue a client_id"));
                return List.of();
            }
            return audit(scope, server.get(), client.get());
        } finally {
            log.info(registrar.deleteRegisteredClients().summary() + " for " + scope.mcpEndpoint());
        }
    }

    private List<AuditIssue> audit(AuditScope scope, AuthorizationServer server, ProbeClient client) {
        OAuthHttp http = scope.oauthHttp();
        TokenAccess access = new TokenAccess(scope.http(), scope.hostBase().request(), authStrategy);
        TokenLedger ledger = new TokenLedger();
        try {
            return issues.issues(new ConsentAudit(server, http, new UnattendedAuthorizer(http, server), access,
                    ledger, scope.skips(), scope.mcpEndpoint()).run(client));
        } finally {
            server.tokenEndpoint().ifPresent(tokenEndpoint -> new TokenRevocation(http,
                    server.revocationEndpoint(), tokenEndpoint, eventLog).revoke(client.credentials(), ledger.issued()));
        }
    }

    private record AuditScope(HttpRequestResponse hostBase, Http http, OAuthHttp oauthHttp, OAuthSkipLog skips,
                              String mcpEndpoint) {
    }
}
