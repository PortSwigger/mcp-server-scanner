package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;

import java.util.List;
import java.util.stream.Stream;

final class ReplySignature {

    private static final String HOST = "§host";
    private static final List<String> LOOPBACK_RENDERINGS = List.of(
            "[0:0:0:0:0:ffff:7f00:1]", "0:0:0:0:0:ffff:7f00:1", "[0:0:0:0:0:ffff:127.0.0.1]",
            "0:0:0:0:0:ffff:127.0.0.1", "[::ffff:127.0.0.1]", "::ffff:127.0.0.1", "[::ffff:7f00:1]",
            "::ffff:7f00:1", "127.0.0.1");

    private ReplySignature() {
    }

    static String of(HttpResponse response, ProbeUrl probe) {
        String text = McpReply.in(response).message().map(ReplySignature::withoutId)
                .orElseGet(response::bodyToString);
        for (String rendering : renderings(probe.host())) {
            text = text.replace(rendering, HOST);
        }
        return response.statusCode() + " " + text.replace(HOST + ":" + probe.port(), HOST + ":§port");
    }

    private static List<String> renderings(String sentHost) {
        return Stream.concat(Stream.of(sentHost, sentHost.replace("[", "").replace("]", "")),
                LOOPBACK_RENDERINGS.stream()).toList();
    }

    private static String withoutId(JsonNode message) {
        JsonNode copy = message.deepCopy();
        if (copy instanceof ObjectNode object) {
            object.remove("id");
        }
        return copy.toString();
    }
}
