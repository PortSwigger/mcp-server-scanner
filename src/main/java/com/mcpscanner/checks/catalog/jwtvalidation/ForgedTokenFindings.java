package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

record ForgedTokenFindings(HttpRequestResponse baseline, HttpRequestResponse malformedBearerRefusal,
                           List<AcceptedForgery> acceptedForgeries, List<ClaimProbe> claimProbes) {

    ForgedTokenFindings {
        acceptedForgeries = List.copyOf(acceptedForgeries);
        claimProbes = List.copyOf(claimProbes);
    }

    AcceptedForgery firstAcceptedForgery() {
        return acceptedForgeries.get(0);
    }
}
