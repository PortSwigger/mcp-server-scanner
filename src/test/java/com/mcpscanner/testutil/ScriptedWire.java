package com.mcpscanner.testutil;

import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpResponse;
import com.mcpscanner.http.evidence.WireRecord;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

final class ScriptedWire {

    private ScriptedWire() {
    }

    static ProtocolHttpResponse attached(ProtocolHttpRequest request, ProtocolHttpResponse response) {
        if (response == null || response.wire().isPresent()) {
            return response;
        }
        return new ProtocolHttpResponse(response.status(), response.headers(), response.body(), response.uri(),
                wireOf(request, response));
    }

    private static Optional<WireRecord> wireOf(ProtocolHttpRequest request, ProtocolHttpResponse response) {
        try {
            HttpRequest sent = asJdkRequest(request);
            byte[] body = request.hasBody() ? request.body().getBytes(StandardCharsets.UTF_8) : new byte[0];
            return Optional.of(WireRecord.ofJdk(sent, body, new ScriptedHead(sent, response)));
        } catch (IllegalArgumentException headerTheJdkClientRefuses) {
            return Optional.empty();
        }
    }

    private static HttpRequest asJdkRequest(ProtocolHttpRequest request) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri()).method(request.method(),
                request.hasBody() ? HttpRequest.BodyPublishers.ofString(request.body())
                        : HttpRequest.BodyPublishers.noBody());
        request.headers().forEach(builder::header);
        return builder.build();
    }

    private record ScriptedHead(HttpRequest request, ProtocolHttpResponse response) implements HttpResponse<Void> {

        @Override
        public int statusCode() {
            return response.status();
        }

        @Override
        public Optional<HttpResponse<Void>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return HttpHeaders.of(response.headers(), (name, value) -> true);
        }

        @Override
        public Void body() {
            return null;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public URI uri() {
            return response.uri();
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }
    }
}
