package com.mcpscanner.http.evidence;

import java.net.http.HttpResponse;
import java.util.List;

public final class LegacySseExchange {

    private LegacySseExchange() {
    }

    public static List<WireRecord> answered(WireRecord post, HttpResponse<?> stream, byte[] event) {
        return List.of(post, WireRecord.streamEvent(stream, event));
    }
}
