package com.mcpscanner.mcp;

import java.util.concurrent.atomic.AtomicLong;

public final class JsonRpcBody {

    private static final AtomicLong REQUEST_ID_SEQUENCE = new AtomicLong();

    private JsonRpcBody() {}

    public static long nextRequestId() {
        return REQUEST_ID_SEQUENCE.incrementAndGet();
    }

    public static String emptyParams(String method) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + nextRequestId()
                + ",\"method\":\"" + escape(method)
                + "\",\"params\":{}}";
    }

    public static String singleStringParam(String method, String paramName, String paramValue) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + nextRequestId()
                + ",\"method\":\"" + escape(method)
                + "\",\"params\":{\"" + escape(paramName) + "\":\"" + escape(paramValue) + "\"}}";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
