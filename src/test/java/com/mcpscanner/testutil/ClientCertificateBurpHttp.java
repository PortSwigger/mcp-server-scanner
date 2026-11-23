package com.mcpscanner.testutil;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Stands in for Burp's networking with a client TLS certificate configured under Settings, Network,
 * TLS: sends each Montoya request body's bytes over real TLS presenting the configured certificate (if
 * any), accepts any upstream server certificate (Burp's default), honours the request's redirection
 * mode and response timeout, and, like Burp, returns a request/response pair with a null response
 * when the connection or handshake fails or no reply arrives in time. Like Burp's default "treat
 * text/event-stream as streaming" setting, it refuses a streamed reply to an extension by throwing
 * {@link #STREAMING_REFUSAL}.
 */
public final class ClientCertificateBurpHttp extends SendOnlyBurpHttp {

    public static final String STREAMING_REFUSAL = "Streaming response received";

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration DEFAULT_RESPONSE_TIMEOUT = Duration.ofSeconds(10);
    private static final Set<String> CLIENT_MANAGED_HEADERS = caseInsensitive("Host", "Content-Length", "Connection");

    private final SSLContext sslContext;

    private ClientCertificateBurpHttp(Optional<KeyStore> clientCertificate) throws GeneralSecurityException {
        this.sslContext = TestPki.clientTrustingAnyServer(clientCertificate);
    }

    public static ClientCertificateBurpHttp presenting(KeyStore clientCertificate) throws GeneralSecurityException {
        return new ClientCertificateBurpHttp(Optional.of(clientCertificate));
    }

    public static ClientCertificateBurpHttp withoutClientCertificate() throws GeneralSecurityException {
        return new ClientCertificateBurpHttp(Optional.empty());
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return HttpRequestResponse.httpRequestResponse(request,
                responseTo(request, RecordingRequestOptions.recorded(requestOptions)));
    }

    private HttpResponse responseTo(HttpRequest request, RecordingRequestOptions options) {
        try {
            return toBurpResponse(clientFor(requiredRedirectionMode(options)).send(toJdkRequest(request, options),
                    java.net.http.HttpResponse.BodyHandlers.ofInputStream()));
        } catch (IOException connectionOrHandshakeFailureOrTimeout) {
            return null;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    private static RedirectionMode requiredRedirectionMode(RecordingRequestOptions options) {
        return options.redirectionMode().orElseThrow(() ->
                new IllegalStateException("Request options must choose a redirection mode"));
    }

    private HttpClient clientFor(RedirectionMode redirectionMode) {
        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .followRedirects(redirectPolicyFor(redirectionMode))
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(CONNECT_TIMEOUT)
                .build();
    }

    private static HttpClient.Redirect redirectPolicyFor(RedirectionMode redirectionMode) {
        return switch (redirectionMode) {
            case NEVER -> HttpClient.Redirect.NEVER;
            case ALWAYS -> HttpClient.Redirect.ALWAYS;
            default -> throw new UnsupportedOperationException("Unsupported redirection mode " + redirectionMode);
        };
    }

    private static java.net.http.HttpRequest toJdkRequest(HttpRequest request, RecordingRequestOptions options) {
        java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder(serviceTarget(request))
                .timeout(options.responseTimeout().orElse(DEFAULT_RESPONSE_TIMEOUT))
                .method(request.method(), bodyOf(request));
        for (HttpHeader header : request.headers()) {
            if (!CLIENT_MANAGED_HEADERS.contains(header.name())) {
                builder.header(header.name(), header.value());
            }
        }
        return builder.build();
    }

    private static URI serviceTarget(HttpRequest request) {
        HttpService service = request.httpService();
        return URI.create((service.secure() ? "https://" : "http://") + service.host() + ":" + service.port()
                + request.path());
    }

    private static java.net.http.HttpRequest.BodyPublisher bodyOf(HttpRequest request) {
        byte[] body = request.body() == null ? new byte[0] : request.body().getBytes();
        return body.length == 0
                ? java.net.http.HttpRequest.BodyPublishers.noBody()
                : java.net.http.HttpRequest.BodyPublishers.ofByteArray(body);
    }

    private static HttpResponse toBurpResponse(java.net.http.HttpResponse<InputStream> response) throws IOException {
        try (InputStream body = response.body()) {
            if (isEventStream(response)) {
                throw new IllegalStateException(STREAMING_REFUSAL);
            }
            return rawResponse(response.statusCode(), response.headers().map(), body.readAllBytes());
        }
    }

    private static boolean isEventStream(java.net.http.HttpResponse<?> response) {
        return response.headers().firstValue("Content-Type")
                .filter(type -> type.toLowerCase(java.util.Locale.ROOT).startsWith("text/event-stream"))
                .isPresent();
    }

    private static Set<String> caseInsensitive(String... names) {
        Set<String> set = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        set.addAll(List.of(names));
        return set;
    }
}
