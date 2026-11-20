package com.mcpscanner.automation;

import java.util.List;
import java.util.Optional;

public record SignedInSessionCommand(List<CommandCookie> cookies, Boolean optIn, CommandScannerClient scannerClient) {

    public static final SignedInSessionCommand NONE = new SignedInSessionCommand(List.of(), null);

    public SignedInSessionCommand {
        cookies = cookies == null ? List.of() : List.copyOf(cookies);
    }

    public SignedInSessionCommand(List<CommandCookie> cookies, Boolean optIn) {
        this(cookies, optIn, null);
    }

    boolean optsIn() {
        return Boolean.TRUE.equals(optIn);
    }

    Optional<CommandScannerClient> client() {
        return Optional.ofNullable(scannerClient);
    }
}
