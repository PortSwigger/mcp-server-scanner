package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.collaborator.CollaboratorPayload;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.collaborator.PayloadSource;
import com.mcpscanner.checks.shared.collaborator.WatchDecision;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

final class OutOfBandShellProbe {

    private static final SkipReason COLLABORATOR_UNAVAILABLE =
            SkipReason.prerequisiteMissing("Burp Collaborator is unavailable");
    private static final SkipReason NO_PAYLOAD = SkipReason.prerequisiteMissing("Burp Collaborator issued no payload");

    private final CollaboratorWatch watch;
    private final CheckLog log;

    OutOfBandShellProbe(CollaboratorWatch watch, CheckLog log) {
        this.watch = watch;
        this.log = log;
    }

    void probe(ProbeField field, Consumer<Finding> onConfirmed) {
        if (!watch.available()) {
            log.notRunOncePerLoad(described(field), COLLABORATOR_UNAVAILABLE);
            return;
        }
        Map<String, SentBreakout> sentByPayloadId = new LinkedHashMap<>();
        List<CollaboratorPayload> payloads = watch.probing(source -> sendBreakouts(field, source, sentByPayloadId));
        PendingProbe pending = new PendingProbe(field.subject(), sentByPayloadId);
        watch.watch(payloads, soFar -> {
            onConfirmed.accept(pending.finding(soFar));
            return WatchDecision.DONE;
        });
    }

    private List<CollaboratorPayload> sendBreakouts(ProbeField field, PayloadSource source,
                                                    Map<String, SentBreakout> sentByPayloadId) {
        List<CollaboratorPayload> payloads = new ArrayList<>();
        for (ShellBreakout breakout : field.breakouts()) {
            if (field.gaveUp()) {
                break;
            }
            Optional<CollaboratorPayload> payload = source.newPayload();
            if (payload.isEmpty()) {
                log.notRun(described(field), NO_PAYLOAD);
                break;
            }
            InjectionReply reply = field.send(breakout.wrap(field.original(), OutOfBandCommand.reaching(payload.get().toString())));
            payloads.add(payload.get());
            sentByPayloadId.put(payload.get().id().toString(), new SentBreakout(breakout, watch.kept(reply.exchange())));
        }
        return payloads;
    }

    private static String described(ProbeField field) {
        return "the out-of-band probes of " + field.described();
    }
}
