package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcMessages;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

final class TargetPage {

    private static final Pattern TITLE = Pattern.compile("(?is)<title[^>]*>\\s*([^<]{4,200}?)\\s*</title>");

    private final Optional<String> title;

    private TargetPage(Optional<String> title) {
        this.title = title;
    }

    static TargetPage fetch(Http http, HttpRequest base) {
        try {
            HttpRequestResponse page = http.sendRequest(base.withMethod("GET").withPath("/").withBody("")
                    .withRemovedHeader("Content-Type").withUpdatedHeader("Accept", "*/*"));
            return new TargetPage(titleOf(page));
        } catch (RuntimeException unreachable) {
            return new TargetPage(Optional.empty());
        }
    }

    boolean shownIn(SentUrl sent) {
        return sent.answered() && title.filter(shown -> texts(sent.exchange().response().bodyToString())
                .anyMatch(text -> TITLE.matcher(text).results().anyMatch(match -> match.group(1).equals(shown))))
                .isPresent();
    }

    private static Optional<String> titleOf(HttpRequestResponse page) {
        if (page == null || page.response() == null || page.response().statusCode() >= 400) {
            return Optional.empty();
        }
        Matcher title = TITLE.matcher(page.response().bodyToString());
        return title.find() ? Optional.of(title.group(1)) : Optional.empty();
    }

    private static Stream<String> texts(String body) {
        return Stream.concat(Stream.of(body), JsonRpcMessages.in(body).stream().flatMap(TargetPage::stringsIn));
    }

    private static Stream<String> stringsIn(JsonNode node) {
        if (node.isTextual()) {
            return Stream.of(node.asText());
        }
        return StreamSupport.stream(node.spliterator(), false).flatMap(TargetPage::stringsIn);
    }
}
