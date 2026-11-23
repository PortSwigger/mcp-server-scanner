package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.api.SignedInSession;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.checks.shared.oauth.SameOriginRedirects;
import com.mcpscanner.checks.shared.oauth.TokenRevocation;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

final class HeadlessConsentProbes {

    private final SignedInRun run;
    private final AuthorizationServer server;
    private final SignedInSession session;
    private final SignedInConsent consent;
    private final CheckLog log;
    private final McpEventLog eventLog;
    private final TokenAccess access;

    HeadlessConsentProbes(SignedInRun run, AuthorizationServer server, SignedInSession session,
                          SignedInConsent consent, CheckLog log, McpEventLog eventLog, TokenAccess access) {
        this.run = run;
        this.server = server;
        this.session = session;
        this.consent = consent;
        this.log = log;
        this.eventLog = eventLog;
        this.access = access;
    }

    List<ConsentFinding> findings() {
        ProbeClientRegistrar registrar =
                new ProbeClientRegistrar(run.oauthHttp(), server.registrationEndpoint().orElseThrow());
        try {
            return findingsRevokingTokens(registrar);
        } finally {
            log.info(registrar.deleteRegisteredClients().summary() + " for " + run.mcpEndpoint());
        }
    }

    private List<ConsentFinding> findingsRevokingTokens(ProbeClientRegistrar registrar) {
        ProbeTokens tokens = new ProbeTokens();
        try {
            return audit(registrar, tokens).run();
        } finally {
            server.tokenEndpoint().ifPresent(tokenEndpoint -> tokens.revoke(new TokenRevocation(run.oauthHttp(),
                    server.revocationEndpoint(), tokenEndpoint, eventLog)));
        }
    }

    private Optional<String> probeScope(ScannerClientAtServer scanner) {
        return scanner.client()
                .map(client -> client.grantedScopes().stream().sorted().collect(Collectors.joining(" ")))
                .filter(granted -> !granted.isEmpty())
                .or(server::scope);
    }

    private SignedInAudit audit(ProbeClientRegistrar registrar, ProbeTokens tokens) {
        UnattendedAuthorizer authorizer = new UnattendedAuthorizer(SameOriginRedirects.carryingCookies(
                run.oauthHttp(), UnattendedAuthorizer.MAX_REDIRECTS, session.cookies()), server);
        ProbeSkips skips = new ProbeSkips(run.skips(), run.mcpEndpoint());
        ScannerClientAtServer scanner = ScannerClientAtServer.of(consent.scannerClient(), server.issuer());
        return new SignedInAudit(
                new SignedInProbeClients(registrar, scanner.client().map(ScannerClient::redirectUri)),
                new ShortcutProbe(server, run.oauthHttp(), authorizer, access, tokens, session.source(),
                        probeScope(scanner)),
                new ScopeUpgradeProbe(server, authorizer, new ScopeGrantJudge(server, run.oauthHttp(), tokens, skips),
                        skips, session.source()),
                skips, scanner);
    }
}
