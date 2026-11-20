package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.oauth.AuthorizationParameters;
import com.mcpscanner.checks.shared.oauth.JsonDocument;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

final class CodeRedeemer {

    private static final String APPLICATION_JSON = "application/json";
    private static final String THREAD_NAME = "mcp-oauth-consent-redemption";
    private static final long CONCURRENT_TIMEOUT_SECONDS = 30;

    private final OAuthHttp http;
    private final URI tokenEndpoint;
    private final URI resource;
    private final ProbeClient client;
    private final TokenLedger ledger;

    CodeRedeemer(OAuthHttp http, URI tokenEndpoint, URI resource, ProbeClient client, TokenLedger ledger) {
        this.http = http;
        this.tokenEndpoint = tokenEndpoint;
        this.resource = resource;
        this.client = client;
        this.ledger = ledger;
    }

    URI tokenEndpoint() {
        return tokenEndpoint;
    }

    Redemption redeem(IssuedCode code) {
        Optional<HttpRequestResponse> exchange = http.postForm(tokenEndpoint,
                AuthorizationParameters.encode(form(code)), APPLICATION_JSON, client.credentials().headers());
        Optional<JsonDocument> tokens = exchange.flatMap(JsonDocument::fromSuccessfulResponse);
        Redemption redemption = new Redemption(tokens.flatMap(document -> document.text("access_token")),
                tokens.flatMap(document -> document.text("refresh_token")), exchange,
                tokens.flatMap(document -> document.text("scope")));
        ledger.record(redemption);
        return redemption;
    }

    List<Redemption> redeemConcurrently(IssuedCode code, int attempts) {
        ExecutorService pool = Executors.newFixedThreadPool(attempts, CodeRedeemer::daemonThread);
        try {
            CountDownLatch start = new CountDownLatch(attempts);
            Callable<Redemption> redemption = () -> redeemTogether(code, start);
            return pool.invokeAll(Collections.nCopies(attempts, redemption), CONCURRENT_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS).stream()
                    .map(CodeRedeemer::outcome)
                    .toList();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return List.of();
        } finally {
            pool.shutdownNow();
        }
    }

    private Redemption redeemTogether(IssuedCode code, CountDownLatch start) throws InterruptedException {
        start.countDown();
        start.await();
        return redeem(code);
    }

    private Map<String, String> form(IssuedCode code) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code.value());
        form.put("redirect_uri", client.callback().toString());
        form.put("code_verifier", code.pkce().verifier());
        form.put("resource", resource.toString());
        return client.credentials().form(form);
    }

    private static Thread daemonThread(Runnable task) {
        Thread thread = new Thread(task, THREAD_NAME);
        thread.setDaemon(true);
        return thread;
    }

    private static Redemption outcome(Future<Redemption> redemption) {
        try {
            return redemption.get();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return Redemption.unanswered();
        } catch (ExecutionException | CancellationException failed) {
            return Redemption.unanswered();
        }
    }
}
