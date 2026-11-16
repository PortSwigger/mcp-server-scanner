package com.mcpscanner.checks.catalog.sqlinjection;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;

final class StatementControl {

    private final Canaries canaries;

    StatementControl(Canaries canaries) {
        this.canaries = canaries;
    }

    boolean runsWholeStatements(ProbeField field) {
        StatementCanary canary = canaries.statement();
        ValueSlot whole = ValueSlot.whole(field.original());
        Probe statement = field.send(whole, canary.statement());
        if (computes(statement, canary)) {
            return true;
        }
        Probe broken = field.send(whole, canary.brokenStatement());
        return statement.shape().differsFrom(broken.shape());
    }

    private static boolean computes(Probe probe, StatementCanary canary) {
        return McpReply.answering(probe.exchange(), McpReply::isResponse).message()
                .map(message -> anyTextContains(message, canary.product()))
                .orElse(false);
    }

    private static boolean anyTextContains(JsonNode node, String text) {
        if (node.isValueNode()) {
            return node.asText().contains(text);
        }
        for (JsonNode child : node) {
            if (anyTextContains(child, text)) {
                return true;
            }
        }
        return false;
    }
}
