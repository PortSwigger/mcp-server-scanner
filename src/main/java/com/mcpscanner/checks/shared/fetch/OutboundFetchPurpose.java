package com.mcpscanner.checks.shared.fetch;

import com.mcpscanner.mcp.McpMethods;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class OutboundFetchPurpose {

    private static final Set<String> NAMED_OPERATIONS_WITH_ARGUMENTS =
            Set.of(McpMethods.TOOLS_CALL, McpMethods.PROMPTS_GET);
    private static final Pattern ARGUMENT_FIELD = Pattern.compile("^MCP field: params\\.arguments\\.([^.\\[]+)$");
    private static final Pattern WORD_BOUNDARY = Pattern.compile("[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])");
    private static final Set<String> FETCHING_VERBS = Set.of("fetch", "browse", "scrape", "download", "http");
    private static final Set<String> GENERIC_FETCH_WORDS = Set.of(
            "fetch", "browse", "scrape", "download", "http", "https", "url", "uri", "web", "page", "webpage",
            "request", "get", "content", "html", "markdown");
    private static final Set<String> URL_ARGUMENT_WORDS = Set.of("url", "uri", "link", "href");

    public boolean fetchesByDesign(String method, Optional<String> operation, String fieldName) {
        if (!NAMED_OPERATIONS_WITH_ARGUMENTS.contains(method)) {
            return false;
        }
        Matcher argument = ARGUMENT_FIELD.matcher(fieldName);
        return argument.matches()
                && operation.filter(OutboundFetchPurpose::genericFetchOperation).isPresent()
                && words(argument.group(1)).stream().anyMatch(URL_ARGUMENT_WORDS::contains);
    }

    private static boolean genericFetchOperation(String operation) {
        List<String> words = words(operation);
        return words.stream().anyMatch(FETCHING_VERBS::contains) && GENERIC_FETCH_WORDS.containsAll(words);
    }

    private static List<String> words(String identifier) {
        return Arrays.stream(WORD_BOUNDARY.split(identifier))
                .filter(word -> !word.isEmpty())
                .map(word -> word.toLowerCase(Locale.ROOT))
                .toList();
    }
}
