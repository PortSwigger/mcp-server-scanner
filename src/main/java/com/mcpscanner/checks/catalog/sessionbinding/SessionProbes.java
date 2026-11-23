package com.mcpscanner.checks.catalog.sessionbinding;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.api.crossidentity.ProbeKit;
import com.mcpscanner.checks.api.crossidentity.TripletArms;
import com.mcpscanner.checks.shared.session.SessionHeaders;

import java.util.List;
import java.util.Optional;

final class SessionProbes {

    private static final String BINDING = "session_binding";
    private static final String REBIND = "session_rebind";

    private final IdentityProbe probe;

    SessionProbes(IdentityProbe probe) {
        this.probe = probe;
    }

    Verdict run() {
        return disposableTrial().orElseGet(this::liveSessionBinding);
    }

    private Optional<Verdict> disposableTrial() {
        ProbeKit kit = probe.kit();
        Optional<HttpRequest> ownerSession = kit.sessions().disposable(kit.requests().as(kit.owner(), kit.seed().request()));
        OperationReply ownerReply = ownerSession.map(probe::reply).orElseGet(OperationReply::none);
        if (!ownerReply.success()) {
            probe.decide(BINDING + ":skipped_rebind_unverified");
            probe.skip(SkipReason.prerequisiteMissing("the owner's call failed in a fresh session"));
            return Optional.of(probe.settled(Verdict.UNSUITABLE_SEED));
        }
        String sessionId = SessionHeaders.carriedBy(ownerSession.get()).orElseThrow();
        OperationReply bearer = probe.reply(SessionHeaders.inSession(kit.anonymousSessionless(), sessionId));
        OperationReply hijacked = probe.reply(SessionHeaders.inSession(probe.asPrincipal(), sessionId));
        Optional<OperationReply> identitysOwnReply = reboundToIdentity(ownerReply, hijacked);
        if (identitysOwnReply.isPresent()) {
            confirmRebind(ownerReply, bearer, hijacked, identitysOwnReply.get());
            probe.decide(BINDING + ":skipped_rebinding_server");
            probe.skip(liveSessionNotProbed("the server rebinds a session to the presented credential"));
            return Optional.of(probe.settled(Verdict.CONCLUSIVE));
        }
        if (!ownerReply.sameResult(probe.reply(ownerSession.get()))) {
            probe.decide(BINDING + ":skipped_disturbed_session");
            probe.skip(liveSessionNotProbed("the trial disturbed the owner's disposable session"));
            return Optional.of(probe.settled(Verdict.CONCLUSIVE));
        }
        return Optional.empty();
    }

    private static SkipReason liveSessionNotProbed(String why) {
        return SkipReason.notApplicable(why + ", so the live session is not probed");
    }

    private Optional<OperationReply> reboundToIdentity(OperationReply ownerReply, OperationReply hijacked) {
        if (!hijacked.accepted() || hijacked.result() == null || ownerReply.sameReply(hijacked)) {
            return Optional.empty();
        }
        Optional<OperationReply> identitysReply = probe.kit().sessions().fresh(probe.asPrincipal())
                .map(probe::reply).filter(hijacked::sameReply);
        if (identitysReply.isEmpty()) {
            probe.decide(REBIND + ":not_peer_reply");
        }
        return identitysReply;
    }

    private void confirmRebind(OperationReply ownerReply, OperationReply bearer, OperationReply hijacked,
                               OperationReply identitysOwnReply) {
        if (!ownerReply.sameResult(bearer)) {
            probe.decide(REBIND + ":session_not_bearer");
            return;
        }
        OperationReply after = probe.reply(bearer.exchange().request());
        OperationReply repeated = probe.reply(bearer.exchange().request());
        if (!after.sameReply(hijacked) || !repeated.sameReply(hijacked) || ownerReply.sameReply(after)) {
            probe.decide(REBIND + ":unchanged");
            return;
        }
        String identity = probe.principal().name();
        probe.report(SessionBindingIssues.rebound(probe.principal(),
                "A credential-free request on a session the scanner opened as the owner returned the owner's result "
                        + "for " + probe.kit().seed().label() + ". After " + identity + "'s credentials were sent once "
                        + "on that session (answered with the same reply " + identity + " gets in its own session), "
                        + "two repeated credential-free requests on the same session returned " + identity
                        + "'s reply instead: " + identity + "'s credential replaced the principal bound to the session. "
                        + "The first request in the evidence is the credential-free request and the second sends "
                        + identity + "'s credential on the session; the third request in the evidence is " + identity
                        + "'s reply in its own session. Of the two repeated requests, the last request in the "
                        + "evidence is the first of them; the second, identical, is not attached. "
                        + "The scanner's own session was not used for this probe.",
                List.of(bearer.exchange(), hijacked.exchange(), identitysOwnReply.exchange(), after.exchange())));
    }

    private Verdict liveSessionBinding() {
        HttpRequest hijack = probe.kit().inCapturedSession(probe.asPrincipal()).orElseThrow();
        if (!probe.ownerResultReturned(BINDING, probe.reply(hijack))) {
            return probe.settled(Verdict.CONCLUSIVE);
        }
        return binding(hijack);
    }

    private Verdict binding(HttpRequest hijack) {
        Optional<HttpRequest> own = probe.kit().sessions().fresh(probe.asPrincipal());
        if (own.isEmpty()) {
            probe.decide(BINDING + ":session_unavailable");
            probe.skip(SkipReason.prerequisiteMissing("the identity's own session could not be opened"));
            return Verdict.INCONCLUSIVE;
        }
        String identity = probe.principal().name();
        probe.kit().triplet().separate(BINDING, new TripletArms(probe.anonymous().request(), hijack, own.get()))
                .filter(separation -> probe.ownerResultReturned(BINDING, separation.candidate()))
                .ifPresent(separation -> probe.report(SessionBindingIssues.ownerResult(probe.principal(),
                        probe.ownerMarkerConfirms(separation.candidate()),
                        identity + "'s credentials presented with the owner's Mcp-Session-Id returned exactly the "
                                + "owner's result for " + probe.kit().seed().label() + ", while " + identity
                                + "'s own session and the anonymous replay did not.",
                        separation.evidence(probe.owner()))));
        return probe.settled(Verdict.CONCLUSIVE);
    }
}
