package com.mcpscanner.checks.shared.probe;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.jsonrpc.ReplyBody;

public final class ServerErrorAnswer {

    private static final int FIRST_SERVER_ERROR = 500;
    private static final int LAST_SERVER_ERROR = 599;

    private ServerErrorAnswer() {}

    public static boolean of(HttpRequestResponse exchange) {
        if (exchange == null || exchange.response() == null) {
            return false;
        }
        int status = exchange.response().statusCode();
        return status >= FIRST_SERVER_ERROR && status <= LAST_SERVER_ERROR;
    }

    public static boolean reproduces(HttpRequestResponse first, HttpRequestResponse repeat) {
        return of(first) && of(repeat) && ReplyBody.sameAnswer(first.response(), repeat.response());
    }
}
