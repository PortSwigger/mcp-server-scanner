package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.net.WebMcpRequests;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.AuthorizationServerDiscovery;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

public final class OAuthRedirectPolicyCheck implements HostCheck {

    private final CheckLog log;
    private final Supplier<AuthStrategy> authStrategy;
    private final OAuthRedirectPolicyIssues issues =
            new OAuthRedirectPolicyIssues(OAuthRedirectPolicyDescriptor.DESCRIPTOR);
    private final List<RedirectProbe> probes = List.of(
            new LoopbackCallbackProbe(),
            new AnyHostRegistrationProbe(),
            new HttpsCallbackProbe(),
            new ScriptSchemeRegistrationProbe(),
            new WildcardHostProbe());

    public OAuthRedirectPolicyCheck(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy) {
        this.log = new CheckLog(eventLog, OAuthRedirectPolicyDescriptor.DESCRIPTOR.id());
        this.authStrategy = authStrategy;
    }

    @Override
    public CheckDescriptor descriptor() {
        return OAuthRedirectPolicyDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean appliesTo(HttpRequestResponse hostBaseRequestResponse) {
        return WebMcpRequests.isWebMcpRequest(hostBaseRequestResponse);
    }

    @Override
    public String appliesOnlyTo() {
        return "MCP requests to an http(s) URL";
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse hostBaseRequestResponse, Http http) {
        OAuthHttp oauthHttp = new OAuthHttp(http);
        OAuthSkipLog skips = new OAuthSkipLog(log, oauthHttp);
        URI mcpEndpoint = URI.create(hostBaseRequestResponse.request().url());
        try {
            return audit(hostBaseRequestResponse, oauthHttp, skips, mcpEndpoint);
        } finally {
            skips.stoppedIfRateLimited(mcpEndpoint.toString());
        }
    }

    private List<AuditIssue> audit(HttpRequestResponse hostBase, OAuthHttp http, OAuthSkipLog skips,
                                   URI mcpEndpoint) {
        Optional<AuthorizationServer> server = new AuthorizationServerDiscovery(http).discover(hostBase);
        if (server.isEmpty() || server.get().registrationEndpoint().isEmpty()) {
            skips.notRun(mcpEndpoint.toString(),
                    SkipReason.prerequisiteMissing("no authorization server with a registration endpoint discovered"));
            return List.of();
        }
        ProbeContext context = context(server.get(), hostBase, mcpEndpoint, http);
        try {
            return issues.issues(findings(context, http, skips, mcpEndpoint));
        } finally {
            log.info(context.registrar().deleteRegisteredClients().summary() + " for " + mcpEndpoint);
        }
    }

    private List<RedirectFinding> findings(ProbeContext context, OAuthHttp http, OAuthSkipLog skips,
                                           URI mcpEndpoint) {
        List<RedirectFinding> findings = new ArrayList<>();
        for (RedirectProbe probe : probes) {
            if (http.rateLimited()) {
                return findings;
            }
            findings.addAll(probe.run(context));
        }
        logMissingClients(context.clients(), skips, mcpEndpoint);
        return findings;
    }

    private static void logMissingClients(OwnedClients clients, OAuthSkipLog skips, URI mcpEndpoint) {
        if (clients.loopback().isEmpty()) {
            skips.notRun("the loopback-callback redirect tests for " + mcpEndpoint, SkipReason.prerequisiteMissing(
                    "dynamic client registration did not register a loopback callback"));
        }
        if (clients.https().isEmpty()) {
            skips.notRun("the any-host registration, https-callback, script-scheme and wildcard redirect tests for "
                    + mcpEndpoint,
                    SkipReason.prerequisiteMissing("dynamic client registration did not register an https callback"));
        }
    }

    private ProbeContext context(AuthorizationServer server, HttpRequestResponse base, URI mcpEndpoint,
                                 OAuthHttp http) {
        ProbeClientRegistrar registrar = new ProbeClientRegistrar(http, server.registrationEndpoint().orElseThrow());
        Map<String, String> session = AuthorizationSession.headersFor(server.authorizationEndpoint(), mcpEndpoint,
                base.request().headerValue("Cookie"), () -> authStrategy.get().headers());
        Authorizer authorizer = new Authorizer(http, new AuthorizationRequestFactory(server), session);
        return new ProbeContext(registrar, new OwnedClients(registrar),
                new DeliveryProbe(authorizer, server.authorizationEndpoint()));
    }
}
