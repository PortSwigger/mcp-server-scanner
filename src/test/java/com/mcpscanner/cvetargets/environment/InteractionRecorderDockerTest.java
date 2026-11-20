package com.mcpscanner.cvetargets.environment;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;

import static com.mcpscanner.testutil.AwaitedFutures.valueWithin;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@Tag("cve-target-lifecycle")
class InteractionRecorderDockerTest {

    private static final Path SOURCE = Path.of("cve-targets/_shared/interaction-recorder").toAbsolutePath();
    private static final Duration COMMAND_TIMEOUT = Duration.ofMinutes(10);
    private static final Duration PROCESS_POLL_INTERVAL = Duration.ofMillis(200);

    @TempDir
    Path workDirectory;

    private final String suffix = HexFormat.of().toHexDigits(ThreadLocalRandom.current().nextInt());
    private final RecorderIdentity identity = new RecorderIdentity("cvet-interaction-recorder-it-" + suffix,
            "10.250.77." + (200 + ThreadLocalRandom.current().nextInt(40)), "mcp-cve-target/interaction-recorder-it:" + suffix);
    private final CommandRunner docker = new ProcessCommandRunner();
    private final List<Process> children = new ArrayList<>();

    @AfterEach
    void removeTheTestRecorder() {
        children.forEach(Process::destroyForcibly);
        docker("rm", "--force", identity.container());
        docker("image", "rm", identity.image());
        docker("volume", "rm", identity.trustVolume());
    }

    @Test
    void aRunStartingAnotherRecorderVersionNeverDisturbsOneInUseAndReplacesItOnceUnused() throws Exception {
        Path locks = workDirectory.resolve("locks");
        Path otherVersion = variantOfTheRecorderSource();

        Process firstRun = startRecorder(SOURCE, locks, true);
        URI admin = URI.create(firstLine(firstRun));
        String inUse = containerId();

        Process overlappingRun = startRecorder(otherVersion, locks, false);
        assertThat(URI.create(firstLine(overlappingRun))).isEqualTo(admin);
        awaitExit(overlappingRun, Duration.ofMinutes(2));
        assertThat(containerId()).as("an overlapping run must reuse the recorder in use").isEqualTo(inUse);
        assertThat(adminStatus(admin)).isEqualTo(200);

        firstRun.getOutputStream().close();
        awaitExit(firstRun, Duration.ofSeconds(30));
        Process laterRun = startRecorder(otherVersion, locks, false);
        firstLine(laterRun);
        awaitExit(laterRun, Duration.ofMinutes(2));
        assertThat(containerId()).as("a run with no other users replaces an outdated recorder").isNotEqualTo(inUse);
    }

    private static void awaitExit(Process run, Duration bound) {
        await().atMost(bound).pollInterval(PROCESS_POLL_INTERVAL).until(() -> !run.isAlive());
    }

    private Path variantOfTheRecorderSource() throws IOException {
        Path variant = Files.createDirectories(workDirectory.resolve("variant"));
        for (String file : List.of("Dockerfile", "recorder.py")) {
            Files.copy(SOURCE.resolve(file), variant.resolve(file));
        }
        Files.writeString(variant.resolve("recorder.py"), "\n# test variant " + suffix + "\n", StandardOpenOption.APPEND);
        return variant;
    }

    private Process startRecorder(Path source, Path locks, boolean keepUsing) throws IOException {
        Process child = new ProcessBuilder(javaBinary(), "-cp", System.getProperty("java.class.path"),
                RecorderStartMain.class.getName(), source.toString(), locks.toString(), identity.container(),
                identity.address(), identity.image(), Boolean.toString(keepUsing))
                .redirectError(ProcessBuilder.Redirect.INHERIT).start();
        children.add(child);
        return child;
    }

    private String containerId() {
        return docker("inspect", "--format", "{{.Id}}", identity.container()).requireSuccess().output().strip();
    }

    private static int adminStatus(URI admin) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(admin.resolve("/interactions?after=0")).build(),
                HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    private CommandResult docker(String... arguments) {
        List<String> command = new ArrayList<>(List.of("docker"));
        command.addAll(List.of(arguments));
        return docker.run(command, workDirectory, COMMAND_TIMEOUT);
    }

    private static String firstLine(Process child) throws Exception {
        BufferedReader output = new BufferedReader(new InputStreamReader(child.getInputStream(), StandardCharsets.UTF_8));
        return valueWithin(COMMAND_TIMEOUT, CompletableFuture.supplyAsync(() -> {
            try {
                return output.readLine();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }));
    }

    private static String javaBinary() {
        return ProcessHandle.current().info().command().orElse("java");
    }

    static final class RecorderStartMain {

        public static void main(String[] arguments) throws IOException {
            RecorderIdentity identity = new RecorderIdentity(arguments[2], arguments[3], arguments[4]);
            URI admin = new InteractionRecorder(new ProcessCommandRunner(), Path.of(arguments[0]), identity,
                    new FileRecorderUsers(Path.of(arguments[1])), System.err::println).start();
            System.out.println(admin);
            System.out.flush();
            if (Boolean.parseBoolean(arguments[5])) {
                System.in.read();
            }
        }
    }
}
