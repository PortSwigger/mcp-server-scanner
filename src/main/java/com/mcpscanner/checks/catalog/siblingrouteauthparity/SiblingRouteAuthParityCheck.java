package com.mcpscanner.checks.catalog.siblingrouteauthparity;

import com.mcpscanner.checks.api.ProbeStops;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.shared.auth.AuthVariantSuite;
import com.mcpscanner.checks.shared.auth.CredentialStripper;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.auth.oracle.SameCatalogItems;
import com.mcpscanner.checks.shared.probe.AuthenticatedBaseline;
import com.mcpscanner.checks.shared.probe.BaselineAcquisition;
import com.mcpscanner.checks.shared.probe.ControlRefusal;
import com.mcpscanner.checks.shared.probe.IndependentSessionSender;
import com.mcpscanner.checks.shared.probe.ProbeChannel;
import com.mcpscanner.checks.shared.session.StreamingFallback;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

public final class SiblingRouteAuthParityCheck implements HostCheck {

    static final int REQUEST_BUDGET = 60;

    private final CheckLog log;
    private final int requestBudget;
    private final AuthVariantSuite suite;
    private final SiblingRoutes routes;
    private final AuthenticatedBaseline authenticatedBaseline;
    private final BaselineEquivalenceOracle oracle = new BaselineEquivalenceOracle(new SameCatalogItems());
    private final SiblingRouteAuthParityIssues issues =
            new SiblingRouteAuthParityIssues(SiblingRouteAuthParityDescriptor.DESCRIPTOR);
    private final StreamingFallback streamedReplies = StreamingFallback.outsideBurp();

    public SiblingRouteAuthParityCheck(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy,
                                       Supplier<Optional<HttpService>> sseProbeService) {
        this(eventLog, authStrategy, sseProbeService, REQUEST_BUDGET);
    }

    SiblingRouteAuthParityCheck(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy,
                                Supplier<Optional<HttpService>> sseProbeService, int requestBudget) {
        this.log = new CheckLog(eventLog, SiblingRouteAuthParityDescriptor.DESCRIPTOR.id());
        this.requestBudget = requestBudget;
        this.suite = new AuthVariantSuite(authStrategy, UUID.randomUUID().toString().substring(0, 12));
        this.routes = new SiblingRoutes(sseProbeService, suite, new CredentialStripper(authStrategy));
        this.authenticatedBaseline = new AuthenticatedBaseline(authStrategy);
    }

    @Override
    public CheckDescriptor descriptor() {
        return SiblingRouteAuthParityDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean appliesTo(HttpRequestResponse hostBaseRequestResponse) {
        return CatalogListing.is(hostBaseRequestResponse.request());
    }

    @Override
    public String appliesOnlyTo() {
        return "catalog listings (tools/list, resources/list, resources/templates/list, prompts/list)";
    }

    @Override
    public List<HostTrial> trials() {
        return List.of(new SiblingRouteTrial(this));
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse hostBaseRequestResponse, Http http) {
        return render(outcomeOf(hostBaseRequestResponse, http));
    }

    AuditOutcome outcomeOf(HttpRequestResponse hostBaseRequestResponse, Http http) {
        ProbeChannel channel = new ProbeChannel(streamedReplies.around(http), requestBudget);
        ProbeStops stops = new ProbeStops(log, channel, SkipSubject.of(hostBaseRequestResponse));
        return auditOver(channel, stops).run(hostBaseRequestResponse);
    }

    List<AuditIssue> render(AuditOutcome outcome) {
        return outcome.finding().map(issues::render).stream().toList();
    }

    private SiblingRouteAudit auditOver(ProbeChannel channel, ProbeStops stops) {
        IndependentSessionSender sender = new IndependentSessionSender(channel, oracle);
        return new SiblingRouteAudit(suite.noCredentialControl(), routes, sender,
                new ControlRefusal(channel, oracle),
                new BaselineAcquisition(authenticatedBaseline, channel, sender, oracle), oracle, stops);
    }
}
