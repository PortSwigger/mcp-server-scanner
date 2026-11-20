package com.mcpscanner.ui.sendto;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.List;
import java.util.function.BiConsumer;

public final class MontoyaSendToDestinations {

    private MontoyaSendToDestinations() {
    }

    public static List<SendToDestination> create(MontoyaApi api) {
        return List.of(
                handOff("Repeater", (request, title) -> api.repeater().sendToRepeater(request, title)),
                handOff("Intruder", (request, title) -> api.intruder().sendToIntruder(request, title)),
                handOff("Organizer", (request, title) -> api.organizer().sendToOrganizer(request)),
                handOff("Comparer", (request, title) -> api.comparer().sendToComparer(request.toByteArray())),
                handOff("Decoder", (request, title) -> api.decoder().sendToDecoder(request.toByteArray())));
    }

    private static SendToDestination handOff(String name, BiConsumer<HttpRequest, String> sender) {
        return SendToDestination.of(name, (request, title) -> sender.accept(withoutScannerFraming(request), title));
    }

    private static HttpRequest withoutScannerFraming(HttpRequest request) {
        return request.hasHeader(ScannerSentinels.FRAMED_OPERATION_HEADER)
                ? request.withRemovedHeader(ScannerSentinels.FRAMED_OPERATION_HEADER)
                : request;
    }
}
