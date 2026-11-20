package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.http.message.HttpRequestResponse;

record SentBreakout(ShellBreakout breakout, HttpRequestResponse exchange) {
}
