package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.collaborator.CollaboratorServer;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.testutil.SpentRateLimitQuota;
import com.mcpscanner.checks.shared.collaborator.FakeCollaborator;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class FilteringFetchTool {

    static final String COLLABORATOR_IP = "198.51.100.7";
    static final String HOME_PAGE = "<html><head><title>Internal admin console</title></head><body>secrets</body></html>";
    static final String REFUSAL = "url must not target a private or local network";
    static final Set<String> DOTTED_ONLY_FILTER = Set.of("127.0.0.1", "0x7f000001", "2130706433", "0177.00.00.01",
            "127.1", "[::ffff:127.0.0.1]");

    private static final Pattern URL_ARGUMENT = Pattern.compile("\"url\":\"(http://(\\[[^\\]]+\\]|[^/:\\[]+)[^\"]*)\"");
    private static final Pattern PAYLOAD = Pattern.compile("/([a-z0-9]+)\\." + Pattern.quote(FakeCollaborator.DOMAIN));

    private final FakeCollaborator collaborator = new FakeCollaborator() {
        @Override
        public CollaboratorServer server() {
            return new CollaboratorServer() {
                @Override
                public String address() {
                    return COLLABORATOR_IP;
                }

                @Override
                public boolean isLiteralAddress() {
                    return true;
                }
            };
        }
    };
    private final List<String> fetchedUrls = new ArrayList<>();
    private final List<HttpRequest> received = new ArrayList<>();
    private Predicate<String> refusedHost = host -> true;
    private Predicate<String> parsedHost = host -> true;
    private Function<String, String> connectFailure = url -> "fetch failed";
    private Predicate<String> servesHomePage = host -> false;
    private int answeredBeforeRateLimit = Integer.MAX_VALUE;
    private int quotaSpentFrom = Integer.MAX_VALUE;
    private IntFunction<String> refusal = received -> REFUSAL;

    FakeCollaborator collaborator() {
        return collaborator;
    }

    FilteringFetchTool refusing(Predicate<String> hosts) {
        this.refusedHost = hosts;
        return this;
    }

    FilteringFetchTool parsingOnly(Predicate<String> hosts) {
        this.parsedHost = hosts;
        return this;
    }

    FilteringFetchTool failingToConnectWith(Function<String, String> message) {
        this.connectFailure = message;
        return this;
    }

    FilteringFetchTool servingTheHomePageOnLoopback() {
        return servingTheHomePageOnLoopbackTo(host -> true);
    }

    FilteringFetchTool servingTheHomePageOnLoopbackTo(Predicate<String> hosts) {
        this.servesHomePage = hosts;
        return this;
    }

    FilteringFetchTool refusingWith(IntFunction<String> textAfterRequests) {
        this.refusal = textAfterRequests;
        return this;
    }

    FilteringFetchTool rateLimitingAfter(int answered) {
        this.answeredBeforeRateLimit = answered;
        return this;
    }

    FilteringFetchTool spendingQuotaFrom(int request) {
        this.quotaSpentFrom = request;
        return this;
    }

    List<String> fetchedUrls() {
        return fetchedUrls;
    }

    List<HttpRequest> received() {
        return received;
    }

    Http http() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> respond(invocation.getArgument(0)));
        return http;
    }

    private HttpRequestResponse respond(HttpRequest request) {
        received.add(request);
        return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(withQuota(answer(request))));
    }

    private String withQuota(String response) {
        if (received.size() < quotaSpentFrom) {
            return response;
        }
        return SpentRateLimitQuota.addedTo(response);
    }

    private String answer(HttpRequest request) {
        if (received.size() > answeredBeforeRateLimit) {
            return "HTTP/1.1 429 Too Many Requests\r\n\r\nslow down";
        }
        if (request.method().equals("GET")) {
            return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + HOME_PAGE;
        }
        Matcher url = URL_ARGUMENT.matcher(request.bodyToString());
        return toolResult(url.find() ? fetch(url.group(1), url.group(2)) : "no url");
    }

    private String fetch(String url, String host) {
        if (!parsedHost.test(host)) {
            return "Invalid URL: " + url;
        }
        if (refusedHost.test(host)) {
            return refusal.apply(received.size());
        }
        fetchedUrls.add(url);
        Matcher payload = PAYLOAD.matcher(url);
        if (payload.find()) {
            collaborator.interact(FakeCollaborator.payload(payload.group(1)), InteractionType.HTTP);
            return "ok";
        }
        return servesHomePage.test(host) ? HOME_PAGE : connectFailure.apply(url);
    }

    private static String toolResult(String text) {
        ObjectNode content = JsonNodeFactory.instance.objectNode().put("type", "text").put("text", text);
        ObjectNode result = JsonNodeFactory.instance.objectNode().put("isError", !text.equals("ok"));
        result.putArray("content").add(content);
        ObjectNode reply = JsonNodeFactory.instance.objectNode().put("jsonrpc", "2.0").put("id", 6);
        reply.set("result", result);
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + reply;
    }
}
