package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;

final class RouteDifferential {

    private final ReplySignature signatures;
    private final AcceptedReply accepted;

    RouteDifferential(ReplySignature signatures, AcceptedReply accepted) {
        this.signatures = signatures;
        this.accepted = accepted;
    }

    Optional<RouteDifference> run(RouteProbe probe, RouteSenders senders) {
        List<SentValue> evidence = new ArrayList<>();
        Optional<String> traversal = agreeingTraversal(probe.traversals(), senders, evidence);
        if (traversal.isEmpty()) {
            return Optional.empty();
        }
        ValueSender sender = senders.confirmations();
        Optional<String> control = agreeing(probe.controls(), sender, evidence, this::anySignature, Optional.empty());
        if (control.isEmpty() || control.equals(traversal)
                || !contrastsDiffer(probe.contrasts(), traversal.get(), sender, evidence)) {
            return Optional.empty();
        }
        boolean repeatable = repeats(probe.traversals().get(0), traversal.get(), sender, accepted::signature)
                && repeats(probe.controls().get(0), control.get(), sender, this::anySignature);
        return repeatable ? Optional.of(new RouteDifference(probe, evidence, control.get())) : Optional.empty();
    }

    private Optional<String> agreeingTraversal(List<String> traversals, RouteSenders senders,
                                               List<SentValue> evidence) {
        return agreeing(traversals.subList(0, 1), senders.probes(), evidence, accepted::signature, Optional.empty())
                .flatMap(candidate -> agreeing(traversals.subList(1, traversals.size()), senders.confirmations(),
                        evidence, accepted::signature, Optional.of(candidate)));
    }

    private static Optional<String> agreeing(List<String> values, ValueSender sender, List<SentValue> evidence,
                                             BiFunction<HttpRequestResponse, String, Optional<String>> signature,
                                             Optional<String> alreadyAgreed) {
        Optional<String> agreed = alreadyAgreed;
        for (String value : values) {
            HttpRequestResponse exchange = sender.send(value);
            Optional<String> observed = signature.apply(exchange, value);
            if (observed.isEmpty() || agreed.isPresent() && !agreed.equals(observed)) {
                return Optional.empty();
            }
            if (agreed.isEmpty()) {
                evidence.add(new SentValue(value, exchange));
            }
            agreed = observed;
        }
        return agreed;
    }

    private boolean contrastsDiffer(List<String> contrasts, String traversal, ValueSender sender,
                                    List<SentValue> evidence) {
        for (String contrast : contrasts) {
            HttpRequestResponse exchange = sender.send(contrast);
            evidence.add(new SentValue(contrast, exchange));
            if (signatures.of(exchange, contrast).equals(traversal)) {
                return false;
            }
        }
        return true;
    }

    private static boolean repeats(String value, String expected, ValueSender sender,
                                   BiFunction<HttpRequestResponse, String, Optional<String>> signature) {
        HttpRequestResponse exchange = sender.send(value);
        return signature.apply(exchange, value).filter(expected::equals).isPresent();
    }

    private Optional<String> anySignature(HttpRequestResponse exchange, String value) {
        return Optional.of(signatures.of(exchange, value));
    }
}
