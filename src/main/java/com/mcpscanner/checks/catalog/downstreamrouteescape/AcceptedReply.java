package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;

final class AcceptedReply {

    private final ReplySignature signatures;
    private final RejectionWording rejections;

    AcceptedReply(ReplySignature signatures, RejectionWording rejections) {
        this.signatures = signatures;
        this.rejections = rejections;
    }

    Optional<String> signature(HttpRequestResponse exchange, String value) {
        return signatures.ofSuccess(exchange, value).filter(signature -> !rejections.statedIn(signature));
    }
}
