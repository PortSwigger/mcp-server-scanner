package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.JsonRpcBody;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class JsonRpcMethodProbeRunner {

    /**
     * Outcome categories for a single JSON-RPC probe.
     *
     * <p>{@link #HTTP_LAYER_ERROR} and {@link #NO_SIGNAL} are kept distinct so callers can tell
     * "the probe didn't reach the server" from "the server responded but the body told us nothing"
     * — e.g. for dedup decisions, which must check {@code HTTP_LAYER_ERROR} explicitly.
     */
    public enum Classification {
        /** Server returned a successful JSON-RPC response with no error envelope. */
        SUSPICIOUS,
        /** Server returned a JSON-RPC error other than -32601 (recognised the method). */
        INTERESTING,
        /** Server returned -32601 Method not found (correct rejection). */
        BORING,
        /** No HTTP response, IOException-class failure, or status != 200. */
        HTTP_LAYER_ERROR,
        /** Status 200 but body neither matches success nor a known error shape. */
        NO_SIGNAL
    }

    public enum ErrorSignal {
        METHOD_NOT_FOUND,    // -32601: dispatcher rejected outright (boring)
        INVALID_PARAMS,      // -32602: method was recognised and dispatched (strong signal)
        INTERNAL_ERROR,      // -32603: generic exception, weak signal
        SERVER_DEFINED,      // -32000..-32099 (server reserved) or non-standard codes
        OTHER_STANDARD,      // remaining standard JSON-RPC error codes (parse / invalid request)
        NONE                 // no error envelope present
    }

    public record ProbeResult(JsonRpcMethodProbe probe,
                              HttpRequestResponse response,
                              Classification classification,
                              Optional<Integer> errorCode,
                              ErrorSignal errorSignal) {}

    private static final int METHOD_NOT_FOUND = -32601;
    private static final int INVALID_PARAMS = -32602;
    private static final int INTERNAL_ERROR = -32603;
    private static final int SERVER_RESERVED_MIN = -32099;
    private static final int SERVER_RESERVED_MAX = -32000;
    private static final int STANDARD_RANGE_MIN = -32768;
    private static final int STANDARD_RANGE_MAX = -32000;

    private final Http http;

    public JsonRpcMethodProbeRunner(Http http) {
        this.http = http;
    }

    public List<ProbeResult> runAll(HttpRequest baseline, List<JsonRpcMethodProbe> probes) {
        List<ProbeResult> results = new ArrayList<>(probes.size());
        for (JsonRpcMethodProbe probe : probes) {
            HttpRequestResponse response = http.sendRequest(
                    baseline.withBody(JsonRpcBody.emptyParams(probe.methodName())));
            results.add(buildResult(probe, response));
        }
        return results;
    }

    private static ProbeResult buildResult(JsonRpcMethodProbe probe, HttpRequestResponse response) {
        if (response.response() == null || response.response().statusCode() != 200) {
            return new ProbeResult(probe, response, Classification.HTTP_LAYER_ERROR,
                    Optional.empty(), ErrorSignal.NONE);
        }
        Optional<Integer> errorCode = McpRequestDetector.extractErrorCode(response);
        if (errorCode.isEmpty()) {
            return new ProbeResult(probe, response,
                    McpRequestDetector.isMethodRecognised(response)
                            ? Classification.SUSPICIOUS
                            : Classification.NO_SIGNAL,
                    Optional.empty(), ErrorSignal.NONE);
        }
        int code = errorCode.get();
        ErrorSignal signal = classifyErrorCode(code);
        return new ProbeResult(probe, response, classificationFor(signal), errorCode, signal);
    }

    /**
     * Only a server-defined code (-32000..-32099 or out-of-range) signals a deliberate handler.
     * -32601 is the correct rejection; -32602 (invalid params) and -32603 (internal error) are
     * what real frameworks return for non-existent methods, so they carry no signal.
     */
    private static Classification classificationFor(ErrorSignal signal) {
        return signal == ErrorSignal.SERVER_DEFINED
                ? Classification.INTERESTING
                : Classification.BORING;
    }

    private static ErrorSignal classifyErrorCode(int code) {
        if (code == METHOD_NOT_FOUND) {
            return ErrorSignal.METHOD_NOT_FOUND;
        }
        if (code == INVALID_PARAMS) {
            return ErrorSignal.INVALID_PARAMS;
        }
        if (code == INTERNAL_ERROR) {
            return ErrorSignal.INTERNAL_ERROR;
        }
        if (code >= SERVER_RESERVED_MIN && code <= SERVER_RESERVED_MAX) {
            return ErrorSignal.SERVER_DEFINED;
        }
        if (code < STANDARD_RANGE_MIN || code > STANDARD_RANGE_MAX) {
            return ErrorSignal.SERVER_DEFINED;
        }
        return ErrorSignal.OTHER_STANDARD;
    }
}
