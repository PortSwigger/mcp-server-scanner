package com.mcpscanner.client;

import com.mcpscanner.core.protocol.HandshakeRefusedException;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.net.SocketTimeoutException;
import java.nio.channels.UnresolvedAddressException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

final class PingFailureClassifier {

    private static final int SESSION_NOT_FOUND = 404;

    private PingFailureClassifier() {
    }

    static PingOutcome classify(Throwable failure) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        PingOutcome found = PingOutcome.INCONCLUSIVE;
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            PingOutcome outcome = classifyOne(cause);
            if (outcome == PingOutcome.SESSION_REFUSED) {
                return outcome;
            }
            if (outcome != PingOutcome.INCONCLUSIVE && found == PingOutcome.INCONCLUSIVE) {
                found = outcome;
            }
        }
        return found;
    }

    private static PingOutcome classifyOne(Throwable failure) {
        if (failure instanceof McpHttpStatusException refusal) {
            return refusal.status() == SESSION_NOT_FOUND ? PingOutcome.SESSION_REFUSED : PingOutcome.INCONCLUSIVE;
        }
        if (failure instanceof HandshakeRefusedException refusal) {
            return refusal.status() == SESSION_NOT_FOUND ? PingOutcome.SESSION_REFUSED : PingOutcome.INCONCLUSIVE;
        }
        if (isUnreachable(failure)) {
            return PingOutcome.UNREACHABLE;
        }
        if (isTimeout(failure)) {
            return PingOutcome.TIMED_OUT;
        }
        return PingOutcome.INCONCLUSIVE;
    }

    private static boolean isUnreachable(Throwable failure) {
        return failure instanceof ConnectException || failure instanceof NoRouteToHostException
                || failure instanceof UnknownHostException || failure instanceof UnresolvedAddressException;
    }

    private static boolean isTimeout(Throwable failure) {
        return failure instanceof HttpTimeoutException || failure instanceof HttpConnectTimeoutException
                || failure instanceof SocketTimeoutException || failure instanceof BurpNoResponseException;
    }
}
