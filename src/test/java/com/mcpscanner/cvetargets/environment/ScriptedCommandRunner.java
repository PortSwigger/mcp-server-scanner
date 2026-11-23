package com.mcpscanner.cvetargets.environment;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

final class ScriptedCommandRunner implements CommandRunner {

    private final Map<String, CommandResult> scripted = new LinkedHashMap<>();
    private final Map<String, Deque<CommandResult>> sequences = new LinkedHashMap<>();
    final List<List<String>> commands = new CopyOnWriteArrayList<>();

    ScriptedCommandRunner on(String subcommand, int exitCode, String output) {
        scripted.put(subcommand, new CommandResult(List.of(subcommand), exitCode, output));
        return this;
    }

    ScriptedCommandRunner onEachCall(String subcommand, CommandResult... results) {
        sequences.put(subcommand, new ArrayDeque<>(List.of(results)));
        return this;
    }

    static CommandResult result(int exitCode, String output) {
        return new CommandResult(List.of(), exitCode, output);
    }

    @Override
    public CommandResult run(List<String> command, Path workingDirectory, Duration timeout) {
        commands.add(command);
        String joined = String.join(" ", command);
        return sequences.entrySet().stream()
                .filter(entry -> joined.contains(entry.getKey()) && !entry.getValue().isEmpty())
                .map(entry -> entry.getValue().size() > 1 ? entry.getValue().poll() : entry.getValue().peek())
                .map(next -> new CommandResult(command, next.exitCode(), next.output()))
                .findFirst()
                .orElseGet(() -> scripted(command, joined));
    }

    private CommandResult scripted(List<String> command, String joined) {
        return scripted.entrySet().stream()
                .filter(entry -> joined.contains(entry.getKey()))
                .map(entry -> new CommandResult(command, entry.getValue().exitCode(), entry.getValue().output()))
                .findFirst()
                .orElse(new CommandResult(command, 0, ""));
    }

    List<String> subcommands() {
        return commands.stream().map(command -> String.join(" ", command)).toList();
    }
}
