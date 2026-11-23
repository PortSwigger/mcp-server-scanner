package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.HostTrialResult;
import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.api.SignedInSession;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.AuthorizationServerDiscovery;
import com.mcpscanner.checks.shared.oauth.HttpUris;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

final class SignedInConsentTrial implements HostTrial {

    private final HostCheck check;
    private final CheckLog log;
    private final McpEventLog eventLog;
    private final Supplier<AuthStrategy> authStrategy;
    private final SignedInConsent consent;
    private final OAuthAuthorizationConsentIssues issues;

    SignedInConsentTrial(HostCheck check, CheckLog log, McpEventLog eventLog, Supplier<AuthStrategy> authStrategy,
                         SignedInConsent consent, OAuthAuthorizationConsentIssues issues) {
        this.check = check;
        this.log = log;
        this.eventLog = eventLog;
        this.authStrategy = authStrategy;
        this.consent = consent;
        this.issues = issues;
    }

    @Override
    public Optional<SkipReason> whyNotApplicable(HttpRequestResponse hostBaseRequestResponse) {
        if (!check.appliesTo(hostBaseRequestResponse)) {
            return Optional.of(SkipReason.notApplicable("applies only to " + check.appliesOnlyTo()));
        }
        return consent.optedIn() ? Optional.empty() : Optional.of(SignedInSkips.OPT_IN_OFF);
    }

    @Override
    public String subject(HttpRequestResponse hostBaseRequestResponse) {
        return "the signed-in consent test on " + SkipSubject.of(hostBaseRequestResponse);
    }

    @Override
    public HostTrialResult run(HttpRequestResponse hostBaseRequestResponse, Http http) {
        OAuthHttp oauthHttp = new OAuthHttp(http);
        SignedInRun run = new SignedInRun(hostBaseRequestResponse, http, oauthHttp,
                new OAuthSkipLog(log, oauthHttp), subject(hostBaseRequestResponse));
        try {
            return HostTrialResult.settled(issues.issues(findings(run)));
        } finally {
            run.skips().stoppedIfRateLimited(run.subject());
        }
    }

    private List<ConsentFinding> findings(SignedInRun run) {
        Optional<AuthorizationServer> server = new AuthorizationServerDiscovery(run.oauthHttp())
                .discover(run.hostBase())
                .filter(discovered -> discovered.registrationEndpoint().isPresent());
        if (server.isEmpty()) {
            run.skips().notRun(run.subject(),
                    SkipReason.prerequisiteMissing("no authorization server with a registration endpoint discovered"));
            return List.of();
        }
        return findings(run, server.get());
    }

    private List<ConsentFinding> findings(SignedInRun run, AuthorizationServer server) {
        Optional<SkipReason> whyNoCookieSession = whyNoCookieSession(run, server);
        whyNoCookieSession.ifPresent(reason -> run.skips().notRun(run.subject(), reason));
        Optional<SignedInSession> session = whyNoCookieSession.isPresent()
                ? Optional.empty()
                : consent.cookieSession(server.authorizationEndpoint());
        if (session.isPresent()) {
            return new HeadlessConsentProbes(run, server, session.get(), consent, log, eventLog,
                    new TokenAccess(run.http(), run.hostBase().request(), authStrategy)).findings();
        }
        List<BrowserConsentObservation> observations = consent.browserObservations(server.authorizationEndpoint());
        if (observations.isEmpty() && whyNoCookieSession.isEmpty()) {
            run.skips().notRun(run.subject(), SignedInSkips.noSession(server.authorizationEndpoint().getHost()));
        }
        return BrowserObservationFindings.findings(observations);
    }

    private static Optional<SkipReason> whyNoCookieSession(SignedInRun run, AuthorizationServer server) {
        if (!HttpUris.isSecureOrLoopback(server.authorizationEndpoint())) {
            return Optional.of(SignedInSkips.plainHttpAuthorization(server.authorizationEndpoint()));
        }
        return server.whyEndpointsLeaveIssuerOrigin()
                .or(() -> whyResourceLeavesMcpOrigin(run, server.resource()))
                .map(SignedInSkips::splitOrigins);
    }

    private static Optional<String> whyResourceLeavesMcpOrigin(SignedInRun run, URI resource) {
        URI mcpEndpoint = URI.create(run.mcpEndpoint());
        return HttpUris.sameOrigin(mcpEndpoint, resource)
                ? Optional.empty()
                : Optional.of("the protected resource " + resource + " is not on the origin of the MCP endpoint "
                        + HttpUris.origin(mcpEndpoint));
    }
}
