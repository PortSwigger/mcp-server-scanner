package com.mcpscanner.signedin;

import com.mcpscanner.auth.oauth.BrowserLauncher;
import com.mcpscanner.auth.oauth.OAuthException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CopyOnWriteArrayList;

final class ScriptedBrowser implements BrowserLauncher {

    enum Reply { CONSENT_PAGE, CODE, CODE_WITH_OTHER_STATE, ACCESS_DENIED, LAUNCH_FAILS, UNLOAD, CODE_AFTER_COLD_START }

    private static final Duration COLD_START = Duration.ofSeconds(3);

    static final String CODE = "code-never-to-log";

    private final List<URI> opened = new CopyOnWriteArrayList<>();
    private final List<Thread> openedOn = new CopyOnWriteArrayList<>();
    private Reply reply = Reply.CONSENT_PAGE;

    ScriptedBrowser replying(Reply reply) {
        this.reply = reply;
        return this;
    }

    List<URI> opened() {
        return List.copyOf(opened);
    }

    List<Thread> openedOn() {
        return List.copyOf(openedOn);
    }

    @Override
    public void open(URI uri) {
        opened.add(uri);
        openedOn.add(Thread.currentThread());
        switch (reply) {
            case CONSENT_PAGE -> { }
            case CODE -> deliver(uri, "code=" + CODE + "&state=" + parameter(uri, "state"));
            case CODE_WITH_OTHER_STATE -> deliver(uri, "code=" + CODE + "&state=forged");
            case ACCESS_DENIED -> deliver(uri, "error=access_denied&state=" + parameter(uri, "state"));
            case LAUNCH_FAILS -> throw new OAuthException("Failed to launch browser: no desktop");
            case UNLOAD -> Thread.currentThread().interrupt();
            case CODE_AFTER_COLD_START -> CompletableFuture.runAsync(
                    () -> deliver(uri, "code=" + CODE + "&state=" + parameter(uri, "state")),
                    CompletableFuture.delayedExecutor(COLD_START.toMillis(), TimeUnit.MILLISECONDS));
        }
    }

    static String parameter(URI uri, String name) {
        return Arrays.stream(uri.getRawQuery().split("&"))
                .map(pair -> pair.split("=", 2))
                .filter(pair -> pair[0].equals(name))
                .map(pair -> URLDecoder.decode(pair[1], StandardCharsets.UTF_8))
                .findFirst()
                .orElse(null);
    }

    static int callbackStatus(URI callback) throws IOException, InterruptedException {
        return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()
                .send(HttpRequest.newBuilder(callback).timeout(Duration.ofSeconds(2)).GET().build(),
                        HttpResponse.BodyHandlers.discarding())
                .statusCode();
    }

    private static void deliver(URI authorizationUrl, String query) {
        try {
            callbackStatus(URI.create(parameter(authorizationUrl, "redirect_uri") + "?" + query));
        } catch (IOException failure) {
            throw new UncheckedIOException(failure);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
