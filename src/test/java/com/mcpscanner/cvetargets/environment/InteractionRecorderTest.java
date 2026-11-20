package com.mcpscanner.cvetargets.environment;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InteractionRecorderTest {

    private static final Path SOURCE = Path.of("cve-targets/_shared/interaction-recorder");
    private static final RecorderIdentity SHARED = RecorderIdentity.SHARED;
    private static final String RUN_BUILT_IMAGE = "docker run --detach --rm --name " + SHARED.container()
            + " --network " + SharedTargetNetwork.NAME + " --ip " + SHARED.address() + " --env RECORDER_ADDRESS="
            + SHARED.address() + " --volume " + SHARED.trustVolume() + ":/trust --publish 127.0.0.1::8080 sha256:built";

    private final List<String> log = new ArrayList<>();

    @Test
    void buildsAndRunsTheRecorderAtItsFixedAddressWhenNoneIsRunning() {
        ScriptedCommandRunner runner = docker().on("docker inspect", 1, "no such container");

        URI admin = recorder(runner, RecorderOccupancy.UNUSED).start();

        assertThat(admin).isEqualTo(URI.create("http://127.0.0.1:49999"));
        assertThat(runner.subcommands()).containsSubsequence(
                "docker build --quiet --provenance=false --tag " + SHARED.image() + " " + SOURCE,
                "docker rm --force " + SHARED.container(),
                RUN_BUILT_IMAGE,
                "docker port " + SHARED.container() + " 8080");
    }

    @Test
    void reusesARunningRecorderOfTheCurrentImage() {
        ScriptedCommandRunner runner = docker().on("docker inspect", 0, "true sha256:built\n");

        recorder(runner, RecorderOccupancy.UNUSED).start();

        assertThat(runner.subcommands()).noneMatch(InteractionRecorderTest::disturbsTheRecorder);
    }

    @Test
    void replacesAnOutdatedRecorderThatNoRunIsUsing() {
        ScriptedCommandRunner runner = docker().on("docker inspect", 0, "true sha256:other\n");

        recorder(runner, RecorderOccupancy.UNUSED).start();

        assertThat(runner.subcommands()).containsSubsequence("docker rm --force " + SHARED.container(), RUN_BUILT_IMAGE);
    }

    @Test
    void keepsAnOutdatedRecorderThatAnotherRunIsUsingAndSaysSo() {
        ScriptedCommandRunner runner = docker().on("docker inspect", 0, "true sha256:other\n");

        URI admin = recorder(runner, RecorderOccupancy.IN_USE).start();

        assertThat(admin).isEqualTo(URI.create("http://127.0.0.1:49999"));
        assertThat(runner.subcommands()).noneMatch(InteractionRecorderTest::disturbsTheRecorder);
        assertThat(log).singleElement().asString()
                .contains(SHARED.container(), "sha256:other", "sha256:built", "in use");
    }

    @Test
    void replacesAStoppedRecorderEvenWhileOtherRunsUseIt() {
        ScriptedCommandRunner runner = docker().on("docker inspect", 0, "false sha256:built\n");

        recorder(runner, RecorderOccupancy.IN_USE).start();

        assertThat(runner.subcommands()).contains(RUN_BUILT_IMAGE);
    }

    @Test
    void inspectsAndReplacesOnlyWhileHoldingTheMachineWideSetUp() {
        ScriptedCommandRunner runner = docker().on("docker inspect", 1, "no such container");
        RecorderUsers neverSetsUp = setup -> { };

        new InteractionRecorder(runner, SOURCE, SHARED, neverSetsUp, log::add).start();

        assertThat(runner.subcommands()).noneMatch(command -> command.startsWith("docker inspect")
                || disturbsTheRecorder(command));
    }

    @Test
    void failsWhenTheRecorderCannotStart() {
        ScriptedCommandRunner runner = docker().on("docker run", 1, "address in use")
                .on("docker inspect", 1, "no such container");

        assertThatThrownBy(() -> recorder(runner, RecorderOccupancy.UNUSED).start())
                .isInstanceOf(EnvironmentException.class);
    }

    private static ScriptedCommandRunner docker() {
        return new ScriptedCommandRunner().on("docker port", 0, "127.0.0.1:49999\n")
                .on("docker build", 0, "sha256:built\n");
    }

    private InteractionRecorder recorder(ScriptedCommandRunner runner, RecorderOccupancy occupancy) {
        return new InteractionRecorder(runner, SOURCE, SHARED, setup -> setup.accept(occupancy), log::add);
    }

    private static boolean disturbsTheRecorder(String command) {
        return command.startsWith("docker run") || command.startsWith("docker rm");
    }
}
