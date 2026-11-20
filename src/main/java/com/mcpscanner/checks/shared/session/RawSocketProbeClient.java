package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.http.wire.SocketHttpTransport;
import com.mcpscanner.http.wire.UnsentRequestException;
import com.mcpscanner.http.wire.WireExchange;
import com.mcpscanner.http.wire.WireRequest;
import com.mcpscanner.http.wire.WireResponse;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;

final class RawSocketProbeClient implements OutsideBurpClient {

    private static final String CONTENT_TYPE = "Content-Type";

    private final SocketHttpTransport transport;
    private final ProbeReplyReader replies;

    RawSocketProbeClient(Duration responseTimeout) {
        this(new SocketHttpTransport(responseTimeout), new ProbeReplyReader(responseTimeout));
    }

    RawSocketProbeClient(SocketHttpTransport transport, ProbeReplyReader replies) {
        this.transport = transport;
        this.replies = replies;
    }

    @Override
    public Optional<HttpRequestResponse> send(HttpRequest request) {
        try {
            WireRequest wire = WireRequest.of(request);
            return Optional.of(exchange(wire, request).evidence());
        } catch (UnsentRequestException | RuntimeException unsent) {
            return Optional.empty();
        }
    }

    private WireRecord exchange(WireRequest wire, HttpRequest request) throws UnsentRequestException {
        try (WireExchange exchange = transport.exchange(wire)) {
            WireResponse response = exchange.response();
            replies.awaitReply(response.headerValue(CONTENT_TYPE), response.body(), request);
            return exchange.record();
        } catch (UnsentRequestException unsent) {
            throw unsent;
        } catch (IOException | RuntimeException unanswered) {
            return WireRecord.unanswered(serviceOf(wire), wire.bytes());
        }
    }

    private static HttpService serviceOf(WireRequest wire) {
        return HttpService.httpService(wire.host(), wire.port(), wire.secure());
    }
}
