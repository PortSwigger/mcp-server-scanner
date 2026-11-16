package com.mcpscanner.checks.catalog.siblingrouteauthparity;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.ProbeStops;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.auth.AuthVariant;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.BaselineAcquisition;
import com.mcpscanner.checks.shared.probe.ControlRefusal;
import com.mcpscanner.checks.shared.probe.IndependentSessionSender;
import com.mcpscanner.checks.shared.probe.NonexistentRouteControl;
import com.mcpscanner.checks.shared.probe.ProbeExchange;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class SiblingRouteAudit {

    private static final SkipReason BASELINE_FAILED =
            SkipReason.prerequisiteMissing("the authenticated catalog listing did not succeed");
    private static final SkipReason NO_CATALOG =
            SkipReason.prerequisiteMissing("the authenticated listing carries no catalog items to compare");
    private static final SkipReason MAIN_ROUTE_OPEN = SkipReason.notApplicable("the main route did not refuse an "
            + "anonymous listing, so there is no refusal to compare sibling routes with");

    private final AuthVariant anonymousMainRoute;
    private final SiblingRoutes routes;
    private final IndependentSessionSender sender;
    private final ControlRefusal controlRefusal;
    private final BaselineAcquisition baselineAcquisition;
    private final BaselineEquivalenceOracle oracle;
    private final NonexistentRouteControl routeControl;
    private final ProbeStops stops;

    SiblingRouteAudit(AuthVariant anonymousMainRoute, SiblingRoutes routes, IndependentSessionSender sender,
                      ControlRefusal controlRefusal, BaselineAcquisition baselineAcquisition,
                      BaselineEquivalenceOracle oracle, ProbeStops stops) {
        this.anonymousMainRoute = anonymousMainRoute;
        this.routes = routes;
        this.sender = sender;
        this.controlRefusal = controlRefusal;
        this.baselineAcquisition = baselineAcquisition;
        this.oracle = oracle;
        this.routeControl = new NonexistentRouteControl(sender, oracle);
        this.stops = stops;
    }

    AuditOutcome run(HttpRequestResponse capturedListing) {
        HttpRequestResponse baseline = baselineOf(capturedListing);
        if (!oracle.successful(baseline)) {
            stops.notRun(BASELINE_FAILED);
            return AuditOutcome.unsuitableSeed();
        }
        if (!carriesCatalog(baseline)) {
            stops.notRun(NO_CATALOG);
            return AuditOutcome.unsuitableSeed();
        }
        Optional<ProbeExchange> refused = mainRouteRefusal(baseline);
        if (refused.isEmpty()) {
            stops.notRun(MAIN_ROUTE_OPEN);
            return AuditOutcome.settledWithoutFinding();
        }
        return AuditOutcome.of(firstOpenRoute(baseline, refused.get()));
    }

    private boolean carriesCatalog(HttpRequestResponse baseline) {
        return oracle.judgeUncontrolled(baseline, baseline).isHit();
    }

    private HttpRequestResponse baselineOf(HttpRequestResponse capturedListing) {
        return CatalogListing.pagesOn(capturedListing.request())
                ? baselineAcquisition.acquireFresh(CatalogListing.firstPage(capturedListing.request()))
                : baselineAcquisition.acquire(capturedListing);
    }

    private Optional<ProbeExchange> mainRouteRefusal(HttpRequestResponse baseline) {
        return controlRefusal.confirm(baseline, sender.sendConfirmingRefusalInAFreshSession(
                anonymousMainRoute.candidate().applyTo(baseline.request())));
    }

    private Optional<Finding> firstOpenRoute(HttpRequestResponse baseline, ProbeExchange refused) {
        for (SiblingRoute route : routes.anonymousRoutesFor(baseline.request())) {
            if (stops.notRunIfExhausted()) {
                return Optional.empty();
            }
            ProbeExchange candidate = sender.send(route.variant().candidate().applyTo(baseline.request()));
            if (!oracle.judgeUncontrolled(baseline, candidate.last()).isHit()) {
                continue;
            }
            Optional<ProbeExchange> control = routeControl.sendFor(route.sweptElsewhereControl(), baseline.request());
            if (route.sweptElsewhere() && !routeControl.suppresses(control)) {
                continue;
            }
            return confirmedStillRefused(baseline)
                    .map(refusedAgain -> new Finding(route, baseline,
                            evidence(baseline, refused, candidate, control, refusedAgain)));
        }
        return Optional.empty();
    }

    private Optional<ProbeExchange> confirmedStillRefused(HttpRequestResponse baseline) {
        return stops.notRunIfExhausted() ? Optional.empty() : mainRouteRefusal(baseline);
    }

    private static List<HttpRequestResponse> evidence(HttpRequestResponse baseline, ProbeExchange refused,
                                                      ProbeExchange candidate, Optional<ProbeExchange> control,
                                                      ProbeExchange refusedAgain) {
        List<HttpRequestResponse> evidence = new ArrayList<>(List.of(baseline, refused.last()));
        evidence.addAll(candidate.exchanges());
        control.ifPresent(exchange -> evidence.add(exchange.last()));
        evidence.add(refusedAgain.last());
        return evidence;
    }
}
