package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CorsProbeTest {

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void preflightIsABodylessOptionsWithOnlyCorsHeadersAndTheSentinel() {
        HttpRequest delivered = AdmissionServers.toolsList(AdmissionServers.LOOPBACK_URL)
                .withHeader("Mcp-Session-Id", "abc")
                .withHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER, ScannerSentinels.SENTINEL_VALUE);

        HttpRequest preflight = new CorsProbe(new CredentialHeaders(NoAuthStrategy::new)).preflightFor(delivered);

        assertThat(preflight.method()).isEqualTo("OPTIONS");
        assertThat(preflight.bodyToString()).isEmpty();
        assertThat(preflight.url()).isEqualTo(AdmissionServers.LOOPBACK_URL);
        assertThat(preflight.headerValue("Origin")).isEqualTo(CorsProbe.FOREIGN_ORIGIN);
        assertThat(preflight.headerValue("Access-Control-Request-Method")).isEqualTo("POST");
        assertThat(preflight.headerValue("Access-Control-Request-Headers")).isEqualTo("content-type,mcp-session-id");
        assertThat(preflight.hasHeader("Mcp-Session-Id")).isFalse();
        assertThat(preflight.hasHeader("Content-Type")).isFalse();
        assertThat(preflight.hasHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER)).isTrue();
    }

    @Test
    void requestsTheBearerHeaderButNeverSendsIt() {
        CredentialHeaders credentials = new CredentialHeaders(() -> new BearerTokenAuthStrategy("secret"));
        HttpRequest delivered = credentials.withMissingAdded(AdmissionServers.toolsList(AdmissionServers.LOOPBACK_URL));

        HttpRequest preflight = new CorsProbe(credentials).preflightFor(delivered);

        assertThat(preflight.headerValue("Access-Control-Request-Headers")).isEqualTo("authorization,content-type");
        assertThat(preflight.hasHeader("Authorization")).isFalse();
    }

    @Test
    void neverRequestsCookieAsAHeader() {
        HttpRequest delivered = AdmissionServers.toolsList(AdmissionServers.LOOPBACK_URL).withHeader("Cookie", "s=1");

        CorsProbe probe = new CorsProbe(new CredentialHeaders(NoAuthStrategy::new));

        assertThat(probe.requestedHeaders(delivered)).containsExactly("content-type");
        assertThat(probe.authOf(delivered)).isEqualTo(CorsAuth.COOKIE);
    }
}
