package com.mcpscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/**
 * The shared not-found-vs-denied differential used by BOTH the tool and resource prefix-sibling
 * runners. A finding requires a distinguishable deny-control AND a not-found sibling; every other
 * combination is FP-safe (no finding).
 */
class FilesystemErrorOracleTest {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void confirmsWhenControlDeniedAndSiblingNotFound() {
        assertThat(FilesystemErrorOracle.prefixSiblingConfirmed(
                deny("Access denied - path outside allowed directories: x not in /srv/ws"),
                notFound("Parent directory does not exist: /srv/ws_mcpscan_x")))
                .isTrue();
    }

    @Test
    void doesNotConfirmWhenSiblingAlsoDenied() {
        // Correctly-bounded server denies the sibling too -> boundary held -> no FP.
        assertThat(FilesystemErrorOracle.prefixSiblingConfirmed(
                deny("Access denied - path outside allowed directories: x not in /srv/ws"),
                deny("Access denied - path outside allowed directories: sib not in /srv/ws")))
                .isFalse();
    }

    @Test
    void doesNotConfirmWhenControlNotDenied_oracleBlind() {
        // not-found-masking server: the control is also not-found, so the oracle cannot tell a
        // missing file from a boundary rejection -> SKIP.
        assertThat(FilesystemErrorOracle.prefixSiblingConfirmed(
                notFound("ENOENT: no such file or directory"),
                notFound("ENOENT: no such file or directory")))
                .isFalse();
    }

    @Test
    void accessDeniedWinsOverNotFoundInTheSameMessage() {
        // A message mentioning both must read as denied (not not-found) so a deny-with-detail is
        // never misclassified as a bypass.
        assertThat(FilesystemErrorOracle.isNotFound(
                deny("Access denied: no such file or directory under the root"))).isFalse();
        assertThat(FilesystemErrorOracle.isAccessDenied(
                deny("Access denied: no such file or directory under the root"))).isTrue();
    }

    @Test
    void transportFailureIsNotNotFound() {
        HttpRequestResponse noResponse = mock(HttpRequestResponse.class);
        lenient().when(noResponse.response()).thenReturn(null);
        assertThat(FilesystemErrorOracle.isNotFound(noResponse)).isFalse();
    }

    private static HttpRequestResponse deny(String message) {
        return errorResponse(message);
    }

    private static HttpRequestResponse notFound(String message) {
        return errorResponse(message);
    }

    private static HttpRequestResponse errorResponse(String message) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\""
                        + message.replace("\"", "\\\"") + "\"}}");
        lenient().when(response.headerValue("Content-Type")).thenReturn("application/json");
        return rr;
    }
}
