package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.HttpRequestResponse;

record SentProbe(ProbeForm form, String value, CollaboratorPayload payload, HttpRequestResponse exchange) {
}
