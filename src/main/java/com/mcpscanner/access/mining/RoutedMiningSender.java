package com.mcpscanner.access.mining;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.access.IdentityRequests;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;

public final class RoutedMiningSender implements MiningSender {

    private final MiningRequests requests;
    private final IdentityRequests identities;
    private final Http http;

    public RoutedMiningSender(MiningRequests requests, IdentityRequests identities, Http http) {
        this.requests = requests;
        this.identities = identities;
        this.http = http;
    }

    @Override
    public MiningReply send(Principal identity, MiningCall call) {
        HttpRequestResponse exchange = http.sendRequest(identities.routed(identity, requests.render(call)));
        return exchange == null || exchange.response() == null ? MiningReply.unanswered()
                : MiningReply.of(exchange.response().statusCode(), McpReply.of(exchange).result());
    }
}
