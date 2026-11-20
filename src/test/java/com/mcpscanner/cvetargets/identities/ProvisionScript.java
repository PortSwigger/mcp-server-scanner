package com.mcpscanner.cvetargets.identities;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.cvetargets.environment.CommandResult;
import com.mcpscanner.cvetargets.environment.CommandRunner;
import com.mcpscanner.cvetargets.environment.Pause;
import com.mcpscanner.cvetargets.manifest.LoadedTarget;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public final class ProvisionScript {

    private static final Duration ATTEMPT_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration RETRY_PAUSE = Duration.ofSeconds(2);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final CommandRunner commands;
    private final Pause pause;
    private final Clock clock;

    public ProvisionScript(CommandRunner commands, Pause pause, Clock clock) {
        this.commands = commands;
        this.pause = pause;
        this.clock = clock;
    }

    public Map<String, ProvisionedIdentity> run(LoadedTarget target, URI endpoint, Duration timeout) {
        String output = outputOf(target, target.manifest().identities().provision(), List.of(endpoint.toString()),
                timeout, "identity provisioning");
        return parse(output);
    }

    String outputOf(LoadedTarget target, String script, List<String> arguments, Duration timeout, String purpose) {
        Instant deadline = clock.instant().plus(timeout);
        CommandResult result = attempt(target, script, arguments);
        while (!result.succeeded() && clock.instant().isBefore(deadline)) {
            pause.pause(RETRY_PAUSE);
            result = attempt(target, script, arguments);
        }
        if (!result.succeeded()) {
            throw new IllegalStateException(purpose + " failed until the readiness timeout: "
                    + OutputLines.tail(result.output()));
        }
        return result.output();
    }

    private CommandResult attempt(LoadedTarget target, String script, List<String> arguments) {
        String path = target.directory().resolve(script).toString();
        List<String> command = Stream.concat(Stream.of(path), arguments.stream()).toList();
        return commands.run(command, target.directory(), ATTEMPT_TIMEOUT);
    }

    private static Map<String, ProvisionedIdentity> parse(String output) {
        try {
            return JSON.readValue(OutputLines.last(output), new TypeReference<>() { });
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("identity provisioning printed no credentials: " + OutputLines.tail(output), e);
        }
    }
}
