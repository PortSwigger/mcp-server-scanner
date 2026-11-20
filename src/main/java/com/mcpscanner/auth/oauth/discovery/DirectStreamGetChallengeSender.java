package com.mcpscanner.auth.oauth.discovery;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

final class DirectStreamGetChallengeSender implements ChallengeSender {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(TIMEOUT)
            .build();

    @Override
    public Optional<ChallengeResponse> send(URI mcpResource) {
        HttpRequest request = HttpRequest.newBuilder(mcpResource)
                .header("Accept", "text/event-stream")
                .timeout(TIMEOUT)
                .GET()
                .build();
        try {
            HttpResponse<java.io.InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            response.body().close();
            return Optional.of(new ChallengeResponse(response.statusCode(),
                    response.headers().firstValue("WWW-Authenticate")));
        } catch (IOException unreachable) {
            return Optional.empty();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }
}
