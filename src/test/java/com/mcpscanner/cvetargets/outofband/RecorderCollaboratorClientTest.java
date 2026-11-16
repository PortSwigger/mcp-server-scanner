package com.mcpscanner.cvetargets.outofband;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class RecorderCollaboratorClientTest {

    private final AtomicReference<String> served = new AtomicReference<>("[]");
    private HttpServer admin;
    private RecorderCollaboratorClient client;

    @BeforeEach
    void startAdmin() throws IOException {
        MontoyaTestFactory.install();
        admin = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        admin.createContext("/interactions", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            byte[] body = (query != null && query.equals("after=0") ? served.get() : "[]")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        admin.start();
        client = new RecorderCollaboratorClient(URI.create("http://127.0.0.1:" + admin.getAddress().getPort()));
    }

    @AfterEach
    void stopAdmin() {
        admin.stop(0);
    }

    @Test
    void mintsDistinctHostsUnderTheRecorderDomainWhoseIdIsTheFirstLabel() {
        CollaboratorPayload first = client.generatePayload();
        CollaboratorPayload second = client.generatePayload();

        assertThat(first.toString()).matches("[a-z0-9]{20}\\.oob\\.cvet\\.test");
        assertThat(first.toString()).startsWith(first.id().toString() + ".");
        assertThat(first.toString()).isNotEqualTo(second.toString());
    }

    @Test
    void translatesRecordedLookupsAndRequests() {
        String raw = "GET /v1/ping?q=1 HTTP/1.1\r\nHost: abc.oob.cvet.test\r\nAuthorization: Bearer t\r\n\r\n";
        served.set("[{\"type\":\"DNS\",\"id\":\"abc\",\"seq\":1,\"time\":1793983572.9,\"clientIp\":\"10.250.77.13\","
                + "\"clientPort\":5353,\"query\":\"abc.oob.cvet.test\",\"queryType\":\"A\"},"
                + "{\"type\":\"HTTP\",\"id\":\"abc\",\"seq\":2,\"time\":1793983573.0,\"clientIp\":\"10.250.77.13\","
                + "\"clientPort\":40000,\"request\":\"" + Base64.getEncoder().encodeToString(
                raw.getBytes(StandardCharsets.ISO_8859_1)) + "\"}]");

        List<Interaction> interactions = client.getAllInteractions();

        assertThat(interactions).extracting(Interaction::type).containsExactly(InteractionType.DNS, InteractionType.HTTP);
        assertThat(interactions).allSatisfy(interaction -> assertThat(interaction.id().toString()).isEqualTo("abc"));
        assertThat(interactions.get(0).clientIp().getHostAddress()).isEqualTo("10.250.77.13");
        assertThat(interactions.get(1).httpDetails().orElseThrow().requestResponse().request().headerValue("Authorization"))
                .isEqualTo("Bearer t");
        assertThat(interactions.get(1).httpDetails().orElseThrow().requestResponse().request().method()).isEqualTo("GET");
    }

    @Test
    void readsOnlyInteractionsAfterTheLastOneSeen() {
        served.set("[{\"type\":\"DNS\",\"id\":\"abc\",\"seq\":1,\"time\":1,\"clientIp\":\"10.0.0.1\",\"clientPort\":1,"
                + "\"query\":\"abc.oob.cvet.test\",\"queryType\":\"AAAA\"}]");

        assertThat(client.getAllInteractions()).hasSize(1);
        assertThat(client.getAllInteractions()).isEmpty();
    }

    @Test
    void namesTheRecordersLiteralAddressAsTheServerSoChecksCanSpellIt() {
        assertThat(client.server().address()).isEqualTo("10.250.77.250");
        assertThat(client.server().isLiteralAddress()).isTrue();
    }

    @Test
    void declaresAShortWindowBecauseTheRecorderIsLocal() {
        assertThat(client.interactionWindow().settle()).isLessThanOrEqualTo(java.time.Duration.ofSeconds(1));
    }
}
