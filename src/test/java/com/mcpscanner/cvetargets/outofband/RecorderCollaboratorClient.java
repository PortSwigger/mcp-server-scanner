package com.mcpscanner.cvetargets.outofband;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.CollaboratorServer;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.PayloadOption;
import burp.api.montoya.collaborator.SecretKey;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.collaborator.InteractionWindow;
import com.mcpscanner.checks.shared.collaborator.InteractionWindowHint;
import com.mcpscanner.cvetargets.environment.RecorderIdentity;
import com.mcpscanner.mcp.McpObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class RecorderCollaboratorClient implements CollaboratorClient, InteractionWindowHint {

    public static final String DOMAIN = "oob.cvet.test";
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final int ID_LENGTH = 20;
    private static final InteractionWindow LOCAL_WINDOW =
            new InteractionWindow(Duration.ofMillis(600), Duration.ofMillis(200));

    private static final int READ_ATTEMPTS = 3;
    private static final HttpClient HTTP = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5)).build();

    private final URI admin;
    private final SecureRandom random = new SecureRandom();
    private long lastSeen;

    public RecorderCollaboratorClient(URI admin) {
        this.admin = admin;
    }

    @Override
    public CollaboratorPayload generatePayload(PayloadOption... options) {
        StringBuilder id = new StringBuilder(ID_LENGTH);
        for (int i = 0; i < ID_LENGTH; i++) {
            id.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
        }
        return new RecorderPayload(id.toString(), DOMAIN);
    }

    @Override
    public CollaboratorPayload generatePayload(String customData, PayloadOption... options) {
        return generatePayload(options);
    }

    @Override
    public synchronized List<Interaction> getAllInteractions() {
        List<Interaction> interactions = new ArrayList<>();
        for (JsonNode entry : pageAfter(lastSeen)) {
            interactions.add(RecordedInteraction.from(entry));
            lastSeen = Math.max(lastSeen, entry.path("seq").asLong());
        }
        return interactions;
    }

    @Override
    public List<Interaction> getInteractions(InteractionFilter filter) {
        return getAllInteractions().stream().filter(interaction -> filter.matches(server(), interaction)).toList();
    }

    @Override
    public CollaboratorServer server() {
        return new CollaboratorServer() {
            @Override
            public String address() {
                return RecorderIdentity.SHARED.address();
            }

            @Override
            public boolean isLiteralAddress() {
                return true;
            }
        };
    }

    @Override
    public SecretKey getSecretKey() {
        throw new UnsupportedOperationException("the local interaction recorder has no secret key");
    }

    @Override
    public InteractionWindow interactionWindow() {
        return LOCAL_WINDOW;
    }

    private JsonNode pageAfter(long seen) {
        IOException last = null;
        for (int attempt = 0; attempt < READ_ATTEMPTS; attempt++) {
            try {
                return McpObjectMapper.INSTANCE.readTree(read(admin.resolve("/interactions?after=" + seen)));
            } catch (IOException e) {
                last = e;
            }
        }
        throw new UncheckedIOException(last);
    }

    private static byte[] read(URI uri) throws IOException {
        try {
            return HTTP.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray()).body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while reading the interaction recorder", e);
        }
    }
}
