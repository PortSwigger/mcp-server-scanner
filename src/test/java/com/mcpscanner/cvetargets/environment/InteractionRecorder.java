package com.mcpscanner.cvetargets.environment;

import com.mcpscanner.cvetargets.outofband.RecorderLauncher;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class InteractionRecorder implements RecorderLauncher {

    private static final String ADMIN_PORT = "8080";
    private static final Duration BUILD_TIMEOUT = Duration.ofMinutes(10);
    private static final Duration COMMAND_TIMEOUT = Duration.ofMinutes(1);

    private final CommandRunner runner;
    private final Path source;
    private final RecorderIdentity identity;
    private final RecorderUsers users;
    private final Consumer<String> log;

    public InteractionRecorder(CommandRunner runner, Path source, RecorderIdentity identity, RecorderUsers users,
                               Consumer<String> log) {
        this.runner = runner;
        this.source = source;
        this.identity = identity;
        this.users = users;
        this.log = log;
    }

    @Override
    public URI start() {
        new SharedTargetNetwork(runner, source).ensureExists();
        String built = build();
        users.setUp(occupancy -> ensureServing(built, occupancy));
        return adminUri();
    }

    private String build() {
        return docker(BUILD_TIMEOUT, "build", "--quiet", "--provenance=false", "--tag", identity.image(),
                source.toString()).requireSuccess().output().strip();
    }

    private void ensureServing(String built, RecorderOccupancy occupancy) {
        RecorderContainer current = RecorderContainer.from(
                docker(COMMAND_TIMEOUT, "inspect", "--format", RecorderContainer.INSPECT_FORMAT, identity.container()));
        if (current.serves(built)) {
            return;
        }
        if (current.running() && occupancy == RecorderOccupancy.IN_USE) {
            log.accept("interaction recorder " + identity.container() + " runs image " + current.image()
                    + ", not this checkout's " + built + "; it is in use by another CVE target run, so it is reused"
                    + " unchanged. The next run that starts while no other run uses it replaces it.");
            return;
        }
        replaceWith(built);
    }

    private void replaceWith(String image) {
        docker(COMMAND_TIMEOUT, "rm", "--force", identity.container());
        docker(COMMAND_TIMEOUT, "run", "--detach", "--rm", "--name", identity.container(),
                "--network", SharedTargetNetwork.NAME, "--ip", identity.address(),
                "--env", "RECORDER_ADDRESS=" + identity.address(),
                "--volume", identity.trustVolume() + ":" + RecorderTrust.RECORDER_DIRECTORY,
                "--publish", "127.0.0.1::" + ADMIN_PORT, image)
                .requireSuccess();
    }

    private URI adminUri() {
        String published = docker(COMMAND_TIMEOUT, "port", identity.container(), ADMIN_PORT).requireSuccess()
                .output().strip();
        String firstBinding = published.lines().findFirst().orElseThrow(
                () -> new EnvironmentException("the interaction recorder published no admin port"));
        return URI.create("http://" + firstBinding);
    }

    private CommandResult docker(Duration timeout, String... arguments) {
        List<String> command = new ArrayList<>(List.of("docker"));
        command.addAll(List.of(arguments));
        return runner.run(command, source, timeout);
    }
}
