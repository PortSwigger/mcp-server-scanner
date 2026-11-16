package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

record CorsGrant(int status, Optional<String> allowOrigin, boolean allowCredentials, Set<String> allowHeaders) {

    static final String ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    static final String ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    static final String ALLOW_HEADERS = "Access-Control-Allow-Headers";

    private static final String WILDCARD = "*";
    private static final String AUTHORIZATION = "authorization";

    CorsGrant {
        allowHeaders = Set.copyOf(allowHeaders);
    }

    static CorsGrant of(HttpRequestResponse exchange) {
        HttpResponse response = exchange == null ? null : exchange.response();
        if (response == null) {
            return new CorsGrant(0, Optional.empty(), false, Set.of());
        }
        return new CorsGrant(response.statusCode(), header(response, ALLOW_ORIGIN),
                header(response, ALLOW_CREDENTIALS).filter("true"::equalsIgnoreCase).isPresent(),
                header(response, ALLOW_HEADERS).map(CorsGrant::names).orElse(Set.of()));
    }

    boolean answered() {
        return status > 0;
    }

    boolean serverError() {
        return status >= 500;
    }

    boolean approvesPreflight(String origin, Collection<String> requestedHeaders) {
        return status >= 200 && status < 300 && approves(origin) && permitsAll(requestedHeaders);
    }

    boolean approves(String origin) {
        return allowOrigin.filter(value -> value.equals(origin) || value.equals(WILDCARD)).isPresent();
    }

    boolean approvesWithCredentials(String origin) {
        return allowCredentials && allowOrigin.filter(origin::equals).isPresent();
    }

    String describe() {
        return ALLOW_ORIGIN + ": " + allowOrigin.orElse("(absent)") + ", " + ALLOW_CREDENTIALS + ": "
                + allowCredentials + (allowHeaders.isEmpty() ? "" : ", " + ALLOW_HEADERS + ": "
                + String.join(", ", allowHeaders.stream().sorted().toList()));
    }

    private boolean permitsAll(Collection<String> requestedHeaders) {
        return requestedHeaders.stream().map(CorsGrant::lower).allMatch(this::permits);
    }

    private boolean permits(String header) {
        return allowHeaders.contains(header) || allowHeaders.contains(WILDCARD) && !header.equals(AUTHORIZATION);
    }

    private static Optional<String> header(HttpResponse response, String name) {
        return Optional.ofNullable(response.headerValue(name)).map(String::trim).filter(value -> !value.isEmpty());
    }

    private static Set<String> names(String list) {
        return Arrays.stream(list.split(",")).map(String::trim).filter(name -> !name.isEmpty())
                .map(CorsGrant::lower).collect(Collectors.toSet());
    }

    private static String lower(String name) {
        return name.toLowerCase(Locale.ROOT);
    }
}
