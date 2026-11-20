package com.mcpscanner.testutil;

import com.mcpscanner.client.ProtocolHttpResponse;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpTransport;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

public final class ScriptedProtocolTransport implements ProtocolHttpTransport {

    private final List<ProtocolHttpRequest> requests = new CopyOnWriteArrayList<>();
    private final List<Duration> timeouts = new CopyOnWriteArrayList<>();
    private final Function<ProtocolHttpRequest, ProtocolHttpResponse> script;

    public ScriptedProtocolTransport(Function<ProtocolHttpRequest, ProtocolHttpResponse> script) {
        this.script = script;
    }

    public static ScriptedProtocolTransport fakeServer() {
        return new ScriptedProtocolTransport(FakeMcpServer::respond);
    }

    @Override
    public ProtocolHttpResponse send(ProtocolHttpRequest request, Duration timeout) throws IOException {
        requests.add(request);
        timeouts.add(timeout);
        try {
            return ScriptedWire.attached(request, script.apply(request));
        } catch (ScriptedIoFailure scripted) {
            throw scripted.failure();
        }
    }

    public List<ProtocolHttpRequest> requests() {
        return requests;
    }

    public List<Duration> timeouts() {
        return timeouts;
    }

    public List<String> methods() {
        return requests.stream().map(FakeMcpServer::method).toList();
    }

    public static final class ScriptedIoFailure extends RuntimeException {
        private final IOException failure;

        public ScriptedIoFailure(IOException failure) {
            this.failure = failure;
        }

        private IOException failure() {
            return failure;
        }
    }
}
