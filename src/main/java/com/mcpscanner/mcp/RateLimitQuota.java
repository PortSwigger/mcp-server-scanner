package com.mcpscanner.mcp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class RateLimitQuota {

    static final Duration SHORTEST_RESET_WORTH_STOPPING_FOR = Duration.ofSeconds(10);
    private static final long FIRST_EPOCH_LIKE_SECONDS = 1_000_000_000L;

    private static final String REMAINING_FIELD = "RateLimit-Remaining";
    private static final String RESET_FIELD = "RateLimit-Reset";
    private static final String STRUCTURED_FIELD = "RateLimit";
    private static final String DICTIONARY_REMAINING = "remaining";
    private static final Pattern WHOLE_NUMBER = Pattern.compile("\\d{1,18}");
    private static final Map<String, Pattern> PARAMETERS = Stream.of(DICTIONARY_REMAINING, "reset", "r", "t")
            .collect(Collectors.toUnmodifiableMap(name -> name, RateLimitQuota::parameterNamed));

    private RateLimitQuota() {
    }

    static boolean spent(HttpResponse response) {
        return response != null && (spentBySeparateFields(response) || spentByStructuredField(response));
    }

    private static boolean spentBySeparateFields(HttpResponse response) {
        return values(response, REMAINING_FIELD).anyMatch(RateLimitQuota::isZero)
                && values(response, RESET_FIELD).anyMatch(RateLimitQuota::isLongEnough);
    }

    private static boolean spentByStructuredField(HttpResponse response) {
        return values(response, STRUCTURED_FIELD).anyMatch(RateLimitQuota::fieldSaysSpent);
    }

    private static boolean fieldSaysSpent(String field) {
        if (field.toLowerCase(Locale.ROOT).contains(DICTIONARY_REMAINING + "=")) {
            return itemSaysSpent(field, DICTIONARY_REMAINING, "reset");
        }
        return Arrays.stream(field.split(",")).anyMatch(item -> itemSaysSpent(item, "r", "t"));
    }

    private static boolean itemSaysSpent(String item, String remaining, String reset) {
        return parameter(item, remaining).filter(RateLimitQuota::isZero).isPresent()
                && parameter(item, reset).filter(RateLimitQuota::isLongEnough).isPresent();
    }

    private static Optional<String> parameter(String item, String name) {
        Matcher matcher = PARAMETERS.get(name).matcher(item);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    private static Pattern parameterNamed(String name) {
        return Pattern.compile("(?:^|[;,\\s])" + name + "\\s*=\\s*([^;,\\s]+)", Pattern.CASE_INSENSITIVE);
    }

    private static boolean isZero(String value) {
        return seconds(value).filter(number -> number == 0).isPresent();
    }

    private static boolean isLongEnough(String value) {
        return seconds(value).filter(number -> number >= SHORTEST_RESET_WORTH_STOPPING_FOR.toSeconds()
                && number < FIRST_EPOCH_LIKE_SECONDS).isPresent();
    }

    private static Optional<Long> seconds(String value) {
        String stripped = value.strip();
        return WHOLE_NUMBER.matcher(stripped).matches() ? Optional.of(Long.parseLong(stripped)) : Optional.empty();
    }

    private static Stream<String> values(HttpResponse response, String name) {
        return response.headers().stream().filter(header -> header.name().equalsIgnoreCase(name))
                .map(HttpHeader::value);
    }
}
