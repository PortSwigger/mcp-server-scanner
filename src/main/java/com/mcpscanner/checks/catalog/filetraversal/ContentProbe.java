package com.mcpscanner.checks.catalog.filetraversal;

import com.mcpscanner.checks.shared.evidence.PayloadHighlights;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

final class ContentProbe {

    private final PayloadSender prober;
    private final PayloadSender confirmer;

    ContentProbe(PayloadSender prober, PayloadSender confirmer) {
        this.prober = prober;
        this.confirmer = confirmer;
    }

    ContentTrial run(List<TraversalPayload> strongestFirst, String missingName) {
        List<TraversalAttempt> attempts = new ArrayList<>();
        List<ConfirmedRead> confirmed = new ArrayList<>();
        for (TraversalPayload payload : strongestFirst) {
            TraversalAttempt attempt = send(prober, payload, payload.value());
            attempts.add(attempt);
            Optional<ConfirmedRead> read = disclosed(attempt) ? confirm(attempt, missingName) : Optional.empty();
            read.ifPresent(confirmed::add);
            if (read.filter(ContentProbe::wholeFile).isPresent()) {
                break;
            }
        }
        ContentTrial trial = new ContentTrial(attempts, confirmed);
        return new ContentTrial(Stream.concat(attempts.stream(), resentRejectedTwins(trial).stream()).toList(),
                confirmed);
    }

    private List<TraversalAttempt> resentRejectedTwins(ContentTrial trial) {
        return trial.confirmedReads().stream()
                .flatMap(read -> trial.literalTwins(read.payload()).stream())
                .filter(TraversalAttempt::rejectedWithoutDisclosure)
                .distinct()
                .map(twin -> send(confirmer, twin.payload(), twin.sentValue()))
                .toList();
    }

    private static boolean disclosed(TraversalAttempt attempt) {
        return attempt.disclosure() != Disclosure.NONE;
    }

    private static boolean wholeFile(ConfirmedRead read) {
        return read.disclosure() == Disclosure.FULL;
    }

    private Optional<ConfirmedRead> confirm(TraversalAttempt candidate, String missingName) {
        TraversalPayload payload = candidate.payload();
        TraversalAttempt missingFile = send(confirmer, payload, payload.missingFileTwin(missingName));
        if (!ranWithoutTheFile(missingFile)) {
            return Optional.empty();
        }
        TraversalAttempt missingDirectory = send(confirmer, payload, payload.missingDirectoryTwin(missingName));
        return ranWithoutTheFile(missingDirectory)
                ? Optional.of(new ConfirmedRead(candidate, List.of(missingFile, missingDirectory)))
                : Optional.empty();
    }

    private static boolean ranWithoutTheFile(TraversalAttempt control) {
        return control.reply().answered() && control.disclosure() == Disclosure.NONE;
    }

    private static TraversalAttempt send(PayloadSender sender, TraversalPayload payload, String value) {
        HttpRequestResponse exchange = sender.send(value);
        TraversalReply reply = TraversalReply.of(exchange);
        HttpRequestResponse highlighted = PayloadHighlights.ofProof(exchange, payload.file().proofsIn(reply.texts()));
        return new TraversalAttempt(payload, value, highlighted, reply);
    }
}
