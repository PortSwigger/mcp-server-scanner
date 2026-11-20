package com.mcpscanner.cvetargets.environment;

import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.TargetArm;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public final class DockerTargetEnvironment implements TargetEnvironment {

    private static final String LOOPBACK = "127.0.0.1";

    private final CommandRunner runner;
    private final ComposeProjectCleaner cleaner;
    private final HostPortProbe hostPorts;
    private final DownloadSource downloads;
    private final HelperNameLeases helperNames;
    private final ComposeNetworkPolicy networkPolicy = new ComposeNetworkPolicy();
    private final RecorderTrust recorderTrust;

    public DockerTargetEnvironment(CommandRunner runner) {
        this(runner, ComposeProjectCleaner.standard());
    }

    DockerTargetEnvironment(CommandRunner runner, HelperNameLeases helperNames) {
        this(runner, ComposeProjectCleaner.standard(), HostPortProbe.BINDING, new HttpDownloadSource(), helperNames);
    }

    DockerTargetEnvironment(CommandRunner runner, ComposeProjectCleaner cleaner) {
        this(runner, cleaner, HostPortProbe.BINDING);
    }

    DockerTargetEnvironment(CommandRunner runner, ComposeProjectCleaner cleaner, HostPortProbe hostPorts) {
        this(runner, cleaner, hostPorts, new HttpDownloadSource());
    }

    DockerTargetEnvironment(CommandRunner runner, ComposeProjectCleaner cleaner, HostPortProbe hostPorts,
                            DownloadSource downloads) {
        this(runner, cleaner, hostPorts, downloads, new HelperNameLeases(System.err::println));
    }

    private DockerTargetEnvironment(CommandRunner runner, ComposeProjectCleaner cleaner, HostPortProbe hostPorts,
                                    DownloadSource downloads, HelperNameLeases helperNames) {
        this.runner = runner;
        this.cleaner = cleaner;
        this.hostPorts = hostPorts;
        this.downloads = downloads;
        this.helperNames = helperNames;
        this.recorderTrust = new RecorderTrust(runner, System.err::println);
    }

    @Override
    public RunningArm start(LoadedTarget target, TargetArm arm) {
        return reserve(target, arm).start();
    }

    @Override
    public ReservedArm reserve(LoadedTarget target, TargetArm arm) {
        ComposeProject project = ComposeProject.forArm(target, arm);
        new DownloadCache(project.downloadsDirectory(), downloads, System.err::println)
                .ensure(target.manifest().downloads());
        DockerCompose declared = new DockerCompose(runner, project);
        String config = declared.config();
        requireSharedNetwork(config);
        DockerCompose compose = recorderTrust.applyTo(declared, project, config);
        Set<String> helpers = ArmServices.helpersOf(ComposeConfigJson.parse(config).path("services"), arm.service());
        HelperNameLeases.Lease lease = helperNames.acquire(target.displayName() + "/" + arm.name(), helpers);
        PreparedArm prepared = new PreparedArm(target, arm, project, compose, config, helpers);
        return new ReservedArm(() -> startLeased(prepared, lease), lease::close);
    }

    private RunningArm startLeased(PreparedArm prepared, HelperNameLeases.Lease lease) {
        try {
            return startPrepared(prepared, lease);
        } catch (RuntimeException | Error startFailure) {
            lease.close();
            throw startFailure;
        }
    }

    private RunningArm startPrepared(PreparedArm prepared, HelperNameLeases.Lease lease) {
        DockerCompose compose = prepared.compose();
        new SharedTargetNetwork(runner, prepared.target().directory()).ensureExists();
        cleaner.clean(compose);
        requireFreeFixedPorts(prepared.config(), prepared.arm().service(), prepared.project().hostPort());
        requireUnheldServiceNames(prepared);
        try {
            compose.up(prepared.arm().service());
            int port = compose.publishedPort(prepared.arm().service(), prepared.arm().endpoint().port());
            return new ComposeArm(compose, cleaner, lease,
                    URI.create("http://" + LOOPBACK + ":" + port + prepared.arm().endpoint().path()));
        } catch (RuntimeException startFailure) {
            tearDownAfter(compose, startFailure);
            throw startFailure;
        }
    }

    private void requireSharedNetwork(String config) {
        List<String> violations = networkPolicy.violations(config);
        if (!violations.isEmpty()) {
            throw new EnvironmentException(String.join("; ", violations));
        }
    }

    private void requireFreeFixedPorts(String config, String service, int harnessChosenPort) {
        List<HostPort> busy = FixedHostPorts.of(config, service, harnessChosenPort).stream()
                .filter(port -> hostPorts.inUse(port.hostIp(), port.port()))
                .toList();
        if (!busy.isEmpty()) {
            throw new EnvironmentException("fixed host port " + busy.stream().map(HostPort::toString)
                    .collect(Collectors.joining(", "))
                    + " is already in use, probably by the same target running from another worktree or by another"
                    + " process; free it before running this arm");
        }
    }

    private void requireUnheldServiceNames(PreparedArm prepared) {
        List<SharedNetworkNames.Holder> held = new SharedNetworkNames(runner, prepared.target().directory())
                .heldElsewhere(prepared.helpers(), prepared.project().name());
        if (!held.isEmpty()) {
            throw new EnvironmentException(held.stream().map(SharedNetworkNames.Holder::describe)
                    .collect(Collectors.joining("; "))
                    + "; that name would resolve to both projects' containers, so stop that project before running"
                    + " this arm");
        }
    }

    private void tearDownAfter(DockerCompose compose, RuntimeException startFailure) {
        try {
            cleaner.clean(compose);
        } catch (RuntimeException teardownFailure) {
            startFailure.addSuppressed(teardownFailure);
        }
    }

    private record PreparedArm(LoadedTarget target, TargetArm arm, ComposeProject project, DockerCompose compose,
                               String config, Set<String> helpers) {
    }

    private record ComposeArm(DockerCompose compose, ComposeProjectCleaner cleaner, HelperNameLeases.Lease lease,
                              URI endpoint) implements RunningArm {

        @Override
        public void close() {
            try (lease) {
                cleaner.clean(compose);
            }
        }
    }
}
