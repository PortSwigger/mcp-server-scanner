package com.mcpscanner.cvetargets.environment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.ManifestFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;

import static com.mcpscanner.cvetargets.environment.ScriptedCommandRunner.result;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

class DockerTargetEnvironmentTest {

    private static final String SHARED_NETWORK_CONFIG =
            "{\"services\":{\"vulnerable\":{}},\"networks\":{\"default\":{\"name\":\"mcp-cve-targets\",\"external\":true}}}";
    private static final String HELPER_DATABASE_CONFIG = "{\"services\":{"
            + "\"vulnerable\":{\"depends_on\":{\"vulnerable-db\":{\"condition\":\"service_healthy\"}}},"
            + "\"vulnerable-db\":{},\"fixed\":{\"depends_on\":{\"fixed-db\":{}}},\"fixed-db\":{}},"
            + "\"networks\":{\"default\":{\"name\":\"mcp-cve-targets\",\"external\":true}}}";
    private static final String SHARED_HELPER_CONFIG = "{\"services\":{"
            + "\"vulnerable\":{\"depends_on\":{\"target-db\":{}}},\"fixed\":{\"depends_on\":{\"target-db\":{}}},"
            + "\"target-db\":{}},\"networks\":{\"default\":{\"name\":\"mcp-cve-targets\",\"external\":true}}}";

    @TempDir
    Path root;

    private final List<String> waiting = new CopyOnWriteArrayList<>();

    @Test
    void startsTheArmServiceOnTheSharedNetworkAndPublishesItsEndpoint() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:49607\n");

        try (RunningArm arm = new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0))) {
            assertThat(arm.endpoint()).isEqualTo(URI.create("http://127.0.0.1:49607/mcp"));
        }

        assertThat(runner.subcommands()).anySatisfy(command -> assertThat(command)
                .containsPattern("--project-name cvet-[0-9a-f]{8}-check-a-target-one-vulnerable ")
                .contains("up --detach --build vulnerable"));
        assertThat(runner.subcommands().get(runner.subcommands().size() - 2))
                .endsWith("down --volumes --remove-orphans --timeout 1");
    }

    @Test
    void givesEveryComposeCommandAnEnvironmentFileWithAFreeHostPort() throws Exception {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        java.util.List<String> composeCommand = runner.commands.get(runner.commands.size() - 1);
        assertThat(runner.commands).filteredOn(command -> command.contains("compose"))
                .allSatisfy(command -> assertThat(command).contains("--env-file"));
        String environment = java.nio.file.Files.readString(
                Path.of(composeCommand.get(composeCommand.indexOf("--env-file") + 1)));
        assertThat(environment).matches("CVET_HOST_PORT=\\d+\\nCVET_DOWNLOADS=.+/\\.cache/downloads\\n");
        int port = Integer.parseInt(environment.lines().findFirst().orElseThrow().substring("CVET_HOST_PORT=".length()));
        assertThat(port).isBetween(1, 65535);
    }

    private static final String RECORDER_RESOLVED_CONFIG = "{\"services\":{"
            + "\"vulnerable\":{\"dns\":[\"10.250.77.250\"]},\"helper\":{}},"
            + "\"networks\":{\"default\":{\"name\":\"mcp-cve-targets\",\"external\":true}}}";

    @Test
    void makesServicesThatResolveThroughTheRecorderTrustItsHttpsCertificate() throws Exception {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, RECORDER_RESOLVED_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        List<String> up = runner.commands.stream().filter(command -> String.join(" ", command).contains(" up "))
                .findFirst().orElseThrow();
        assertThat(up).containsSubsequence("--file", target().composeFile().toString(), "--file");
        JsonNode override = new ObjectMapper().readTree(
                Path.of(up.get(up.lastIndexOf("--file") + 1)).toFile());
        assertThat(override.path("services").fieldNames()).toIterable().containsExactly("vulnerable");
        JsonNode vulnerable = override.path("services").path("vulnerable");
        assertThat(vulnerable.path("environment").path("SSL_CERT_FILE").asText())
                .isEqualTo("/etc/cvet-recorder-trust/bundle.pem");
        assertThat(vulnerable.path("environment").fieldNames()).toIterable()
                .contains("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
                .doesNotContain("NODE_EXTRA_CA_CERTS");
        assertThat(vulnerable.path("environment").path("NODE_OPTIONS").asText()).isEqualTo("--use-openssl-ca");
        String trustVolume = RecorderIdentity.SHARED.trustVolume();
        assertThat(vulnerable.path("volumes").get(0).path("source").asText()).isEqualTo(trustVolume);
        assertThat(vulnerable.path("volumes").get(0).path("read_only").asBoolean()).isTrue();
        assertThat(override.path("volumes").path(trustVolume).path("external").asBoolean()).isTrue();
    }

    @Test
    void leavesTargetsUnchangedWhenTheRecorderPublishedNoTrustBundle() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, RECORDER_RESOLVED_CONFIG)
                .on("volume inspect " + RecorderIdentity.SHARED.trustVolume(), 1, "no such volume")
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        assertThat(runner.commands).filteredOn(command -> command.contains("compose"))
                .allSatisfy(command -> assertThat(command).containsOnlyOnce("--file"));
    }

    @Test
    void leavesTargetsThatDoNotResolveThroughTheRecorderUnchanged() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        assertThat(runner.commands).filteredOn(command -> command.contains("compose"))
                .allSatisfy(command -> assertThat(command).containsOnlyOnce("--file"));
    }

    @Test
    void createsTheSharedNetworkWithItsFixedSubnetWhenMissing() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("network inspect", 1, "not found")
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        assertThat(runner.subcommands()).contains("docker network create --subnet 10.250.77.0/24 mcp-cve-targets");
    }

    @Test
    void refusesAComposeFileThatWouldCreateItsOwnNetworkBeforeStartingAnything() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, "{\"services\":{\"vulnerable\":{}},\"networks\":{\"default\":{\"name\":\"x_default\"}}}");

        assertThatThrownBy(() -> new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)))
                .hasMessageContaining("must be external and named mcp-cve-targets");
        assertThat(runner.subcommands()).noneMatch(command -> command.contains(" up "));
    }

    @Test
    void tearsDownWhenStartingFails() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("up --detach", 1, "build failed");

        assertThatThrownBy(() -> new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)))
                .hasMessageContaining("build failed");
        assertThat(runner.subcommands()).anyMatch(command -> command.contains(" down "));
    }

    @Test
    void reportsContainersLeftAfterTeardown() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n")
                .onEachCall("ps --all --quiet", result(0, ""), result(0, "abc123\n"));
        RunningArm arm = new DockerTargetEnvironment(runner, new ComposeProjectCleaner(pause -> { }, 3,
                Duration.ofSeconds(1))).start(target(), target().manifest().arms().get(0));

        assertThatThrownBy(arm::close).hasMessageContaining("containers left after teardown: [abc123]");
    }

    @Test
    void removesAStaleProjectBeforeStartingTheArm() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        List<String> commands = runner.subcommands();
        int firstDown = indexOf(commands, " down ");
        int up = indexOf(commands, " up --detach");
        assertThat(firstDown).isNotNegative().isLessThan(up);
    }

    @Test
    void waitsForHelperContainersStillBeingRemovedBeforeReportingACleanTeardown() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n")
                .onEachCall("ps --all --quiet", result(0, ""), result(0, "helper1\n"), result(0, ""));
        List<Duration> pauses = new ArrayList<>();
        DockerTargetEnvironment environment = new DockerTargetEnvironment(runner,
                new ComposeProjectCleaner(pauses::add, 5, Duration.ofSeconds(1)));

        environment.start(target(), target().manifest().arms().get(0)).close();

        assertThat(pauses).containsExactly(Duration.ofSeconds(1));
    }

    @Test
    void refusesToStartWhenAFixedHostPortIsAlreadyInUseAndSaysWhich() {
        String fixedPortConfig = "{\"services\":{\"vulnerable\":{\"ports\":[{\"host_ip\":\"127.0.0.1\",\"target\":8000,"
                + "\"published\":\"47321\"}]}},\"networks\":{\"default\":{\"name\":\"mcp-cve-targets\",\"external\":true}}}";
        ScriptedCommandRunner runner = new ScriptedCommandRunner().on("config --format json", 0, fixedPortConfig);
        DockerTargetEnvironment environment = new DockerTargetEnvironment(runner, ComposeProjectCleaner.standard(),
                (host, port) -> port == 47321);

        assertThatThrownBy(() -> environment.start(target(), target().manifest().arms().get(0)))
                .isInstanceOf(EnvironmentException.class)
                .hasMessageContaining("fixed host port 127.0.0.1:47321 (service vulnerable) is already in use");
        assertThat(runner.subcommands()).noneMatch(command -> command.contains(" up "));
    }

    @Test
    void checksFixedPortsOnlyAfterRemovingItsOwnStaleProject() {
        String fixedPortConfig = "{\"services\":{\"vulnerable\":{\"ports\":[{\"host_ip\":\"127.0.0.1\",\"target\":8000,"
                + "\"published\":\"47321\"}]}},\"networks\":{\"default\":{\"name\":\"mcp-cve-targets\",\"external\":true}}}";
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, fixedPortConfig)
                .on("port vulnerable 8000", 0, "127.0.0.1:47321\n");
        List<String> order = new ArrayList<>();
        DockerTargetEnvironment environment = new DockerTargetEnvironment(runner, ComposeProjectCleaner.standard(),
                (host, port) -> {
                    order.add("probe after " + runner.subcommands().stream().filter(command -> command.contains(" down ")).count() + " down");
                    return false;
                });

        environment.start(target(), target().manifest().arms().get(0)).close();

        assertThat(order).containsExactly("probe after 1 down");
    }

    @Test
    void refusesToStartWhenAnotherProjectOnTheSharedNetworkAnswersToAServiceNameTheArmStarts() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, HELPER_DATABASE_CONFIG)
                .on("ps --filter network=mcp-cve-targets", 0,
                        "acc-copy-vulnerable-db-1\tacc-copy\tvulnerable-db\nunrelated-1\tother\tweb\n");

        assertThatThrownBy(() -> new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)))
                .isInstanceOf(EnvironmentException.class)
                .hasMessageContaining("service name vulnerable-db is already on the shared network mcp-cve-targets,"
                        + " held by container acc-copy-vulnerable-db-1 (project acc-copy)");
        assertThat(runner.subcommands()).noneMatch(command -> command.contains(" up "));
    }

    @Test
    void anArmSharingAHelperWithARunningArmOfThisRunWaitsForItsTeardownBeforeStarting() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_HELPER_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n")
                .on("port fixed 8000", 0, "127.0.0.1:2\n");
        DockerTargetEnvironment environment = new DockerTargetEnvironment(runner, new HelperNameLeases(waiting::add));
        LoadedTarget target = target();
        RunningArm vulnerable = environment.start(target, target.manifest().arms().get(0));

        CompletableFuture<RunningArm> fixed =
                CompletableFuture.supplyAsync(() -> environment.start(target, target.manifest().arms().get(1)));
        await().atMost(Duration.ofSeconds(5)).until(() -> !waiting.isEmpty());
        assertThat(fixed).isNotDone();
        assertThat(runner.subcommands()).noneMatch(command -> command.contains("up --detach --build fixed"));

        vulnerable.close();

        await().atMost(Duration.ofSeconds(5)).until(fixed::isDone);
        fixed.join().close();
        assertThat(runner.subcommands()).anyMatch(command -> command.contains("up --detach --build fixed"));
    }

    @Test
    void reservingAnArmHoldsItsHelperNamesUntilTheReservationCloses() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_HELPER_CONFIG)
                .on("port fixed 8000", 0, "127.0.0.1:2\n");
        DockerTargetEnvironment environment = new DockerTargetEnvironment(runner, new HelperNameLeases(waiting::add));
        LoadedTarget target = target();
        ReservedArm vulnerable = environment.reserve(target, target.manifest().arms().get(0));

        CompletableFuture<RunningArm> fixed =
                CompletableFuture.supplyAsync(() -> environment.start(target, target.manifest().arms().get(1)));
        await().atMost(Duration.ofSeconds(5)).until(() -> !waiting.isEmpty());
        assertThat(fixed).isNotDone();

        vulnerable.close();

        await().atMost(Duration.ofSeconds(5)).until(fixed::isDone);
        fixed.join().close();
    }

    @Test
    void releasesTheHelperNamesWhenStartingFails() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_HELPER_CONFIG)
                .on("up --detach --build vulnerable", 1, "build failed")
                .on("port fixed 8000", 0, "127.0.0.1:2\n");
        DockerTargetEnvironment environment = new DockerTargetEnvironment(runner);
        LoadedTarget target = target();
        assertThatThrownBy(() -> environment.start(target, target.manifest().arms().get(0)))
                .hasMessageContaining("build failed");

        assertThat(CompletableFuture.supplyAsync(() -> environment.start(target, target.manifest().arms().get(1))))
                .succeedsWithin(Duration.ofSeconds(5))
                .satisfies(RunningArm::close);
    }

    @Test
    void startsWhenTheSharedNameHolderIsAServiceTheArmDoesNotStart() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, HELPER_DATABASE_CONFIG)
                .on("ps --filter network=mcp-cve-targets", 0, "acc-copy-fixed-db-1\tacc-copy\tfixed-db\n")
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        assertThat(runner.subcommands()).anyMatch(command -> command.contains("up --detach --build vulnerable"));
    }

    @Test
    void startsWhenAnotherProjectHoldsOnlyTheArmServiceNameWhichNoContainerResolves() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, HELPER_DATABASE_CONFIG)
                .on("ps --filter network=mcp-cve-targets", 0, "manual-vulnerable-1\tmanual\tvulnerable\n")
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        assertThat(runner.subcommands()).anyMatch(command -> command.contains("up --detach --build vulnerable"));
    }

    @Test
    void checksSharedNamesOnlyAfterRemovingItsOwnStaleProject() {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, HELPER_DATABASE_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");

        new DockerTargetEnvironment(runner).start(target(), target().manifest().arms().get(0)).close();

        List<String> commands = runner.subcommands();
        assertThat(indexOf(commands, " down ")).isNotNegative()
                .isLessThan(indexOf(commands, "ps --filter network=mcp-cve-targets"));
    }

    @Test
    void downloadsTheTargetsArtifactsIntoTheCacheBeforeAnyComposeCommand() throws Exception {
        ScriptedCommandRunner runner = new ScriptedCommandRunner()
                .on("config --format json", 0, SHARED_NETWORK_CONFIG)
                .on("port vulnerable 8000", 0, "127.0.0.1:1\n");
        byte[] artifact = "package contents".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        List<Integer> commandsBeforeRetrieval = new ArrayList<>();
        DownloadSource source = (url, destination) -> {
            commandsBeforeRetrieval.add(runner.commands.size());
            java.nio.file.Files.write(destination, artifact);
        };
        LoadedTarget target = targetDownloading(artifact);

        new DockerTargetEnvironment(runner, ComposeProjectCleaner.standard(), HostPortProbe.BINDING, source)
                .start(target, target.manifest().arms().get(0)).close();

        assertThat(commandsBeforeRetrieval).containsExactly(0);
        assertThat(java.nio.file.Files.readAllBytes(root.toRealPath().resolve(".cache/downloads/package.tgz")))
                .isEqualTo(artifact);
    }

    private LoadedTarget targetDownloading(byte[] artifact) throws Exception {
        String integrity = "sha512-" + java.util.Base64.getEncoder().encodeToString(
                java.security.MessageDigest.getInstance("SHA-512").digest(artifact));
        ManifestFixtures.writeTarget(root, "check-a", "target-one", ManifestFixtures.VALID_MANIFEST
                .formatted("target-one", "check-a")
                .replace("\"schemaVersion\": 1,", "\"schemaVersion\": 1, \"downloads\": [{\"file\": \"package.tgz\", "
                        + "\"url\": \"https://registry.example.test/package.tgz\", \"integrity\": \"" + integrity + "\"}],"));
        return ManifestFixtures.loadOnly(root, "check-a", "target-one");
    }

    private static int indexOf(List<String> commands, String fragment) {
        for (int index = 0; index < commands.size(); index++) {
            if (commands.get(index).contains(fragment)) {
                return index;
            }
        }
        return -1;
    }

    private LoadedTarget target() {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        return ManifestFixtures.loadOnly(root, "check-a", "target-one");
    }
}
