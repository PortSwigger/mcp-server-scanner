package com.mcpscanner.http.wire;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.TestPki;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class SocketHttpTransportTest {

    private static final Duration READ_TIMEOUT = Duration.ofSeconds(5);
    private static final String FOREIGN_HOST = "attacker.example";

    private static TestPki pki;

    @BeforeAll
    static void generatePki(@TempDir Path directory) throws Exception {
        pki = TestPki.generate(directory);
    }

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void sendsAForeignHostHeaderVerbatimOverAConnectionToTheServiceHost() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replying();
             WireExchange exchange = new SocketHttpTransport(READ_TIMEOUT)
                     .exchange(foreignHostRequest("http://127.0.0.1:" + server.port()))) {

            assertThat(server.received().head()).contains("\r\nHost: " + FOREIGN_HOST + "\r\n");
            assertThat(exchange.response().status()).isEqualTo(200);
            assertThat(body(exchange)).isEqualTo("ok");
        }
    }

    @Test
    void recordsTheBytesItWroteAndEveryRawByteTheCallerRead() throws Exception {
        String reply = "HTTP/1.1 200 Fine\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "2\r\nok\r\n0\r\n\r\n";
        try (OneConnectionServer server = OneConnectionServer.replyingWith(reply)) {
            WireRequest sent = foreignHostRequest("http://127.0.0.1:" + server.port());
            try (WireExchange exchange = new SocketHttpTransport(READ_TIMEOUT).exchange(sent)) {
                assertThat(body(exchange)).isEqualTo("ok");

                var evidence = exchange.record().evidence();

                assertThat(evidence.request().toByteArray().getBytes()).isEqualTo(sent.bytes());
                assertThat(server.received().head()).isEqualTo(headOf(sent));
                assertThat(new String(evidence.response().toByteArray().getBytes(), StandardCharsets.ISO_8859_1))
                        .isEqualTo(reply);
                assertThat(evidence.request().httpService().port()).isEqualTo(server.port());
            }
        }
    }

    @Test
    void aReplyThatNeverArrivesIsASentFailure() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.silent()) {
            SocketHttpTransport transport = new SocketHttpTransport(Duration.ofMillis(300));

            assertThatThrownBy(() -> transport.exchange(foreignHostRequest("http://127.0.0.1:" + server.port())))
                    .isInstanceOf(SocketTimeoutException.class)
                    .isNotInstanceOf(UnsentRequestException.class);
            assertThat(server.received().head()).startsWith("GET /mcp HTTP/1.1\r\n");
        }
    }

    @Test
    void aRefusedConnectionIsUnsent() throws Exception {
        int closedPort = closedPort();

        assertThatThrownBy(() -> new SocketHttpTransport(READ_TIMEOUT)
                .exchange(foreignHostRequest("http://127.0.0.1:" + closedPort)))
                .isInstanceOf(UnsentRequestException.class);
    }

    @Test
    void namesTheServiceHostInSniWhileTheHostHeaderNamesAnotherHost() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replyingOverTls(serverTls());
             WireExchange exchange = new SocketHttpTransport(READ_TIMEOUT, clientTrustingTestCa())
                     .exchange(foreignHostRequest("https://localhost:" + server.port()))) {

            OneConnectionServer.Received received = server.received();
            assertThat(received.serverName()).contains("localhost");
            assertThat(received.head()).contains("\r\nHost: " + FOREIGN_HOST + "\r\n");
            assertThat(exchange.response().status()).isEqualTo(200);
        }
    }

    @Test
    void sendsNoSniForAnIpLiteralServiceHost() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replyingOverTls(serverTls());
             WireExchange exchange = new SocketHttpTransport(READ_TIMEOUT, clientTrustingTestCa())
                     .exchange(foreignHostRequest("https://127.0.0.1:" + server.port()))) {

            assertThat(server.received().serverName()).isEmpty();
            assertThat(exchange.response().status()).isEqualTo(200);
        }
    }

    @Test
    void verifiesTheServiceHostAgainstTheCertificateLikeTheJdkClient() throws Exception {
        RecordingSslSocketFactory recording = new RecordingSslSocketFactory(clientTrustingTestCa());
        try (OneConnectionServer server = OneConnectionServer.replyingOverTls(serverTls());
             WireExchange ignored = new SocketHttpTransport(READ_TIMEOUT, recording)
                     .exchange(foreignHostRequest("https://localhost:" + server.port()))) {

            assertThat(recording.lastSocket().getSSLParameters().getEndpointIdentificationAlgorithm())
                    .isEqualTo("HTTPS");
        }
    }

    @Test
    void anUntrustedCertificateIsAnUnsentFailure() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replyingOverTls(serverTls())) {
            SocketHttpTransport transport = new SocketHttpTransport(READ_TIMEOUT);

            assertThatThrownBy(() -> transport.exchange(foreignHostRequest("https://localhost:" + server.port())))
                    .isInstanceOf(UnsentRequestException.class);
            assertThatThrownBy(server::received).hasRootCauseInstanceOf(IOException.class);
        }
    }

    @Test
    void aTlsHandshakeDrippedSlowerThanTheConnectTimeoutIsUnsent() throws Exception {
        try (DrippingTlsRecordServer server = DrippingTlsRecordServer.start()) {
            SocketHttpTransport transport = new SocketHttpTransport(READ_TIMEOUT, Duration.ofMillis(300),
                    clientTrustingTestCa());

            assertThatThrownBy(() -> assertTimeoutPreemptively(Duration.ofSeconds(3),
                    () -> transport.exchange(foreignHostRequest("https://localhost:" + server.port()))))
                    .isInstanceOf(UnsentRequestException.class);
        }
    }

    private static WireRequest foreignHostRequest(String origin) {
        return WireRequest.of(HttpRequest.httpRequestFromUrl(origin + "/mcp").withHeader("Host", FOREIGN_HOST));
    }

    private static SSLContext serverTls() throws Exception {
        return pki.serverRequiringClientCertificateOnDefaultTls().getSSLContext();
    }

    private static SSLSocketFactory clientTrustingTestCa() throws Exception {
        return pki.clientTrustingCa(Optional.empty()).getSocketFactory();
    }

    private static int closedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    private static String headOf(WireRequest request) {
        String whole = new String(request.bytes(), StandardCharsets.ISO_8859_1);
        return whole.substring(0, whole.indexOf("\r\n\r\n") + 4);
    }

    private static String body(WireExchange exchange) throws IOException {
        return new String(exchange.response().body().readAllBytes(), StandardCharsets.UTF_8);
    }
}
