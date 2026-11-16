package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CorsGrantTest {

    private static final String ORIGIN = CorsProbe.FOREIGN_ORIGIN;
    private static final List<String> REQUESTED = List.of("content-type", "mcp-session-id");

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void aWildcardPreflightWithEveryHeaderApproves() {
        assertThat(grant(204, "Access-Control-Allow-Origin: *", "Access-Control-Allow-Headers: *")
                .approvesPreflight(ORIGIN, REQUESTED)).isTrue();
    }

    @Test
    void aReflectedOriginWithListedHeadersApproves() {
        assertThat(grant(200, "Access-Control-Allow-Origin: " + ORIGIN,
                "Access-Control-Allow-Headers: Content-Type, Mcp-Session-Id").approvesPreflight(ORIGIN, REQUESTED))
                .isTrue();
    }

    @Test
    void aPreflightMissingARequestedHeaderDoesNotApprove() {
        assertThat(grant(204, "Access-Control-Allow-Origin: *", "Access-Control-Allow-Headers: content-type")
                .approvesPreflight(ORIGIN, REQUESTED)).isFalse();
    }

    @Test
    void aWildcardHeaderListDoesNotCoverAuthorization() {
        assertThat(grant(204, "Access-Control-Allow-Origin: *", "Access-Control-Allow-Headers: *")
                .approvesPreflight(ORIGIN, List.of("authorization"))).isFalse();
    }

    @Test
    void aRefusedPreflightDoesNotApproveEvenWithHeaders() {
        assertThat(grant(405, "Access-Control-Allow-Origin: *", "Access-Control-Allow-Headers: *")
                .approvesPreflight(ORIGIN, REQUESTED)).isFalse();
    }

    @Test
    void anotherOriginIsNotApproved() {
        assertThat(grant(200, "Access-Control-Allow-Origin: http://localhost:3000").approves(ORIGIN)).isFalse();
    }

    @Test
    void credentialedApprovalNeedsTheExactOriginAndCredentialsTrue() {
        assertThat(grant(200, "Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true")
                .approvesWithCredentials(ORIGIN)).isFalse();
        assertThat(grant(200, "Access-Control-Allow-Origin: " + ORIGIN, "Access-Control-Allow-Credentials: true")
                .approvesWithCredentials(ORIGIN)).isTrue();
        assertThat(grant(200, "Access-Control-Allow-Origin: " + ORIGIN).approvesWithCredentials(ORIGIN)).isFalse();
    }

    @Test
    void anUnansweredExchangeGrantsNothing() {
        CorsGrant grant = CorsGrant.of(HttpRequestResponse.httpRequestResponse(
                AdmissionServers.toolsList(AdmissionServers.LOOPBACK_URL), null));

        assertThat(grant.answered()).isFalse();
        assertThat(grant.approves(ORIGIN)).isFalse();
    }

    private static CorsGrant grant(int status, String... headers) {
        String head = "HTTP/1.1 " + status + " X\r\n" + String.join("\r\n", headers) + "\r\n\r\n";
        return CorsGrant.of(HttpRequestResponse.httpRequestResponse(
                AdmissionServers.toolsList(AdmissionServers.LOOPBACK_URL), HttpResponse.httpResponse(head)));
    }
}
