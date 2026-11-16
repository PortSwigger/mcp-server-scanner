package com.mcpscanner.access;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.function.BooleanSupplier;

public interface IdentityBinding {

    IdentityBinding ROUTED = (principal, credentialed) ->
            credentialed.withAddedHeader(ScannerSentinels.IDENTITY_HEADER, principal.id());

    HttpRequest bind(Principal principal, HttpRequest credentialed);

    static IdentityBinding routedWhen(BooleanSupplier routed, IdentityBinding direct) {
        return (principal, credentialed) -> (routed.getAsBoolean() ? ROUTED : direct).bind(principal, credentialed);
    }
}
