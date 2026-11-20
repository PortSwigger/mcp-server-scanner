package com.mcpscanner.cvetargets.environment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.StreamSupport;

public final class RecorderTrust {

    private static final String VOLUME = RecorderIdentity.SHARED.trustVolume();
    static final String RECORDER_DIRECTORY = "/trust";
    private static final String MOUNT = "/etc/cvet-recorder-trust";
    private static final String BUNDLE = MOUNT + "/bundle.pem";
    private static final List<String> BUNDLE_VARIABLES = List.of("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE");
    private static final Map<String, String> NODE_READS_THE_OPENSSL_STORE = Map.of("NODE_OPTIONS", "--use-openssl-ca");
    private static final Duration QUERY_TIMEOUT = Duration.ofMinutes(1);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final CommandRunner runner;
    private final Consumer<String> log;

    public RecorderTrust(CommandRunner runner, Consumer<String> log) {
        this.runner = runner;
        this.log = log;
    }

    DockerCompose applyTo(DockerCompose compose, ComposeProject project, String resolvedConfig) {
        List<String> resolving = servicesResolvingThroughRecorder(ComposeConfigJson.parse(resolvedConfig));
        if (resolving.isEmpty()) {
            return compose;
        }
        if (!published(project.directory())) {
            log.accept("the interaction recorder published no HTTPS trust bundle (volume " + VOLUME
                    + " is missing), so " + project.name() + " cannot reach it over HTTPS");
            return compose;
        }
        return compose.withOverride(writeOverride(project, resolving));
    }

    private static List<String> servicesResolvingThroughRecorder(JsonNode config) {
        return config.path("services").properties().stream()
                .filter(service -> resolvesThroughRecorder(service.getValue()))
                .map(Map.Entry::getKey)
                .toList();
    }

    private static boolean resolvesThroughRecorder(JsonNode service) {
        return StreamSupport.stream(service.path("dns").spliterator(), false)
                .anyMatch(server -> RecorderIdentity.SHARED.address().equals(server.asText()));
    }

    private boolean published(Path workingDirectory) {
        return runner.run(List.of("docker", "volume", "inspect", VOLUME), workingDirectory, QUERY_TIMEOUT)
                .exitCode() == 0;
    }

    private static Path writeOverride(ComposeProject project, List<String> services) {
        ObjectNode override = JSON.createObjectNode();
        ObjectNode overridden = override.putObject("services");
        services.forEach(service -> trusting(overridden.putObject(service)));
        override.putObject("volumes").putObject(VOLUME).put("external", true).put("name", VOLUME);
        try {
            Path file = Files.createTempFile(project.name() + "-recorder-trust", ".json");
            file.toFile().deleteOnExit();
            return Files.writeString(file, override.toString());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write the recorder trust override", e);
        }
    }

    private static void trusting(ObjectNode service) {
        ObjectNode environment = service.putObject("environment");
        BUNDLE_VARIABLES.forEach(variable -> environment.put(variable, BUNDLE));
        NODE_READS_THE_OPENSSL_STORE.forEach(environment::put);
        service.putArray("volumes").addObject()
                .put("type", "volume").put("source", VOLUME).put("target", MOUNT).put("read_only", true);
    }
}
