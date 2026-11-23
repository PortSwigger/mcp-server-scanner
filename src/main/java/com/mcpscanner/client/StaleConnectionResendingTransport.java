package com.mcpscanner.client;

import com.mcpscanner.mcp.ResendableRequests;

import java.io.IOException;
import java.time.Duration;
import java.util.function.Predicate;

public final class StaleConnectionResendingTransport implements ProtocolHttpTransport {

    private final ProtocolHttpTransport delegate;
    private final Predicate<ProtocolHttpRequest> resendable;

    private StaleConnectionResendingTransport(ProtocolHttpTransport delegate,
                                              Predicate<ProtocolHttpRequest> resendable) {
        this.delegate = delegate;
        this.resendable = resendable;
    }

    static StaleConnectionResendingTransport always(ProtocolHttpTransport delegate) {
        return when(delegate, request -> true);
    }

    public static StaleConnectionResendingTransport when(ProtocolHttpTransport delegate,
                                                         Predicate<ProtocolHttpRequest> resendable) {
        return new StaleConnectionResendingTransport(delegate, resendable);
    }

    public static StaleConnectionResendingTransport whenResendable(ProtocolHttpTransport delegate,
                                                                   ResendableRequests resendableRequests) {
        return when(delegate, request -> resendableRequests.resendable(request.method(), request.body()));
    }

    @Override
    public ProtocolHttpResponse send(ProtocolHttpRequest request, Duration timeout)
            throws IOException, InterruptedException {
        try {
            return delegate.send(request, timeout);
        } catch (IOException failure) {
            if (!StaleConnection.closedBeforeReply(failure) || !resendable.test(request)) {
                throw failure;
            }
            return delegate.send(request, timeout);
        }
    }
}
