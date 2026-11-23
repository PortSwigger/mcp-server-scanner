package com.mcpscanner.checks.shared.auth.oracle;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcEnvelope;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcMessages;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;
import com.mcpscanner.checks.shared.jsonrpc.ReplyBody;

import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

final class ExchangeClassifier {

    private static final Set<Integer> REFUSAL_STATUSES = Set.of(401, 403, 404);
    private static final Set<Integer> BLOCK_PAGE_STATUSES = Set.of(403, 404);
    private static final Pattern HTML_PAGE =
            Pattern.compile("\\s*<(?:!doctype\\s+html|html)\\b", Pattern.CASE_INSENSITIVE);

    ExchangeOutcome classify(HttpRequestResponse exchange) {
        if (exchange == null || exchange.response() == null) {
            return ExchangeOutcome.inconclusive(0);
        }
        JsonRpcEnvelope request = JsonRpcEnvelope.of(exchange.request());
        HttpResponse response = exchange.response();
        int status = response.statusCode();
        String body = ReplyBody.text(response);
        if (REFUSAL_STATUSES.contains(status) || RefusalText.refusesBody(body, JsonRpcMessages.in(body))) {
            return ExchangeOutcome.refused(status);
        }
        if (status < 200 || status > 299 || !request.singleMessage()) {
            return ExchangeOutcome.inconclusive(status);
        }
        if (request.id().isEmpty()) {
            return ExchangeOutcome.successful(status, Optional.empty());
        }
        return McpReply.answering(exchange, JsonRpcMessages::isJsonRpc2).successfulResult()
                .map(result -> ExchangeOutcome.successful(status, Optional.of(result)))
                .orElseGet(() -> ExchangeOutcome.inconclusive(status));
    }

    boolean refusedByAuthentication(HttpRequestResponse exchange) {
        if (!classify(exchange).refused()) {
            return false;
        }
        if (!BLOCK_PAGE_STATUSES.contains((int) exchange.response().statusCode())) {
            return true;
        }
        return !HTML_PAGE.matcher(ReplyBody.text(exchange.response())).lookingAt();
    }

    boolean isNotification(HttpRequestResponse exchange) {
        return exchange != null && JsonRpcEnvelope.of(exchange.request()).notification();
    }
}
