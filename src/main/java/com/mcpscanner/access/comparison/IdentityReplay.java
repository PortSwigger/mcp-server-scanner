package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.api.crossidentity.ProtocolVariant;

import java.util.Optional;

final class IdentityReplay {

    private static final String PROBE = "peer_replay";

    private final PrincipalProbe probe;
    private final Replay replay;

    IdentityReplay(PrincipalProbe probe, Replay replay) {
        this.probe = probe;
        this.replay = replay;
    }

    IdentityReach reach() {
        ProtocolVariant captured = ProtocolVariant.asCaptured();
        if (replay.request().isEmpty()) {
            return IdentityReach.unreached(replay.reply(), captured);
        }
        if (probe.ownerResultReturned(PROBE, replay.reply())) {
            return IdentityReach.reached(replay.reply(), replay.request().get(), captured);
        }
        return replay.reply().success() ? IdentityReach.unreached(replay.reply(), captured) : downgraded();
    }

    IdentityReach atOlderVersions() {
        if (replay.request().isEmpty() || replay.reply().success()) {
            return IdentityReach.unreached(replay.reply(), ProtocolVariant.asCaptured());
        }
        return downgraded();
    }

    private IdentityReach downgraded() {
        IdentityReach reach = IdentityReach.unreached(replay.reply(), ProtocolVariant.asCaptured());
        for (ProtocolVariant variant : ProtocolVariant.downgradesFor(probe.kit().seed())) {
            Optional<HttpRequest> request = probe.kit().sessions().fresh(variant.apply(probe.asPrincipal()));
            if (request.isEmpty()) {
                probe.decide(PROBE + ":session_unavailable");
                return reach;
            }
            OperationReply reply = probe.reply(request.get());
            if (probe.ownerResultReturned(PROBE, reply)) {
                return accepted(IdentityReach.reached(reply, request.get(), variant));
            }
            reach = IdentityReach.unreached(reply, variant);
            if (reply.success()) {
                return reach;
            }
        }
        return reach;
    }

    private IdentityReach accepted(IdentityReach reach) {
        probe.decide(PROBE + ":accepted_at_protocol_" + reach.variant().label());
        return anonymousOpenAt(reach.variant()) ? reach.withdrawn() : reach;
    }

    private boolean anonymousOpenAt(ProtocolVariant variant) {
        HttpRequest anonymous = variant.apply(probe.kit().anonymousSessionless());
        HttpRequest request = probe.kit().sessions().fresh(anonymous).orElse(anonymous);
        if (!probe.reply(request).success()) {
            return false;
        }
        probe.decide(PROBE + ":anonymous_success_at_protocol_" + variant.label());
        return true;
    }
}
