package com.mcpscanner.checks.catalog.downstreamrouteescape;

import java.util.List;

final class LocalDirectoryOracle {

    static final List<String> EXISTING_DIRECTORIES = List.of("/etc/", "/usr/");
    static final String MISSING_DIRECTORY = "/mcp-route-escape-missing/";

    private final ReplySignature signatures;
    private final AcceptedReply accepted;

    LocalDirectoryOracle(ReplySignature signatures, AcceptedReply accepted) {
        this.signatures = signatures;
        this.accepted = accepted;
    }

    boolean explains(RouteDifference difference, ValueSender sender) {
        String control = difference.controlSignature();
        return EXISTING_DIRECTORIES.stream().allMatch(directory -> opens(directory, control, sender))
                && control.equals(signatures.of(sender.send(MISSING_DIRECTORY), MISSING_DIRECTORY));
    }

    private boolean opens(String directory, String control, ValueSender sender) {
        return accepted.signature(sender.send(directory), directory).filter(opened -> !opened.equals(control))
                .isPresent();
    }
}
