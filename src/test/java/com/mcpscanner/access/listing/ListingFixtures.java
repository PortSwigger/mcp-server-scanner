package com.mcpscanner.access.listing;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.access.SyntheticCall;
import com.mcpscanner.access.SyntheticCallLog;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.Map;
import java.util.Set;

import static com.mcpscanner.access.AccessFixtures.ALICE;
import static org.mockito.Mockito.mock;

final class ListingFixtures {

    static final Principal PRIMARY = ALICE;
    static final Principal NO_CREDENTIAL = Principal.anonymous();
    static final Principal FAKE_TOKEN = Principal.fakeToken(() -> Map.of("Authorization", "Bearer invalid_abc123"));

    private ListingFixtures() {
    }

    static ToolList tools(Principal principal, String... names) {
        return new ToolList(principal, Set.of(names));
    }

    static SyntheticCall substantiveCall(Principal principal, String tool) {
        return substantiveCall(principal, tool, mock(HttpRequestResponse.class));
    }

    static SyntheticCall substantiveCall(Principal principal, String tool, HttpRequestResponse exchange) {
        return call(principal, tool, AccessOutcome.DIFFERENT_RESULT, new OperationReply(exchange, true,
                json("{\"content\":[{\"type\":\"text\",\"text\":\"users: alice, bob\"}]}"), ""));
    }

    static SyntheticCall emptyCall(Principal principal, String tool) {
        return call(principal, tool, AccessOutcome.DIFFERENT_RESULT,
                new OperationReply(mock(HttpRequestResponse.class), true, json("{\"content\":[]}"), ""));
    }

    static SyntheticCall refusedCall(Principal principal, String tool) {
        return call(principal, tool, AccessOutcome.REFUSED,
                new OperationReply(mock(HttpRequestResponse.class), false, null, "401:"));
    }

    static SyntheticCallLog log(SyntheticCall... calls) {
        SyntheticCallLog log = new SyntheticCallLog();
        for (SyntheticCall call : calls) {
            log.accept(call);
        }
        return log;
    }

    private static SyntheticCall call(Principal principal, String tool, AccessOutcome outcome, OperationReply reply) {
        return new SyntheticCall(new AccessItemKey(AccessItemKey.Kind.TOOL, tool), principal, outcome, reply);
    }

    private static JsonNode json(String value) {
        try {
            return McpObjectMapper.INSTANCE.readTree(value);
        } catch (Exception invalid) {
            throw new IllegalArgumentException(invalid);
        }
    }
}
