package com.mcpscanner.auth.oauth.safety;

import java.net.URI;
import java.util.List;

/**
 * Gatekeeper consulted before every outbound OAuth-discovery fetch. Resolves the destination
 * host, classifies each resolved address (loopback, link-local, RFC1918, cloud-metadata,
 * multicast, cross-origin, etc.), and returns either an ALLOW decision or a DENY decision
 * with a structured {@link Reason}.
 *
 * <p>Implementations may prompt the user for confirmation on classifications that warrant
 * human review; HARD-blocked classifications (invalid scheme, unresolvable, etc.) must never
 * prompt and must always deny.
 *
 * <p>The gate is opt-out: callers that have audited their own destinations can pass an
 * always-allow instance to skip enforcement (e.g. the SSRF-observation scan check).
 */
public interface SuspiciousDestinationGate {

    Decision evaluate(URI url, FetchPurpose purpose);

    enum DecisionKind { ALLOW, DENY }

    /** Outcome of a gate evaluation. */
    record Decision(DecisionKind kind, Reason reason) {

        public static Decision allow() {
            return new Decision(DecisionKind.ALLOW, null);
        }

        public static Decision deny(Reason reason) {
            return new Decision(DecisionKind.DENY, reason);
        }

        public boolean isAllowed() {
            return kind == DecisionKind.ALLOW;
        }

        public boolean isDenied() {
            return kind == DecisionKind.DENY;
        }
    }

    /**
     * Structured reason a destination was rejected (or surfaced for confirmation).
     *
     * @param destination       the URL that was evaluated.
     * @param resolvedAddress   the IP literal the destination resolved to, or {@code null}
     *                          when resolution failed or hasn't happened (e.g. invalid scheme).
     * @param classifications   suspicious classifications that triggered the prompt or deny.
     * @param purpose           the purpose snapshot the caller passed in.
     * @param userMessage       a short, user-facing summary suitable for an event-log line.
     */
    record Reason(URI destination,
                  String resolvedAddress,
                  List<String> classifications,
                  FetchPurpose purpose,
                  String userMessage) {

        public Reason {
            classifications = classifications == null ? List.of() : List.copyOf(classifications);
        }
    }
}
