package com.mcpscanner.scan;

import java.util.Map;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

public final class SendToConnectionPolicy implements Supplier<ScanConnection> {

    private final BooleanSupplier handleAuthentication;
    private final Supplier<ScanConnection> managedConnection;
    private final Supplier<Map<String, String>> currentCredentials;

    public SendToConnectionPolicy(BooleanSupplier handleAuthentication, Supplier<ScanConnection> managedConnection,
                                  Supplier<Map<String, String>> currentCredentials) {
        this.handleAuthentication = Objects.requireNonNull(handleAuthentication);
        this.managedConnection = Objects.requireNonNull(managedConnection);
        this.currentCredentials = Objects.requireNonNull(currentCredentials);
    }

    public boolean handlesAuthentication() {
        return handleAuthentication.getAsBoolean();
    }

    @Override
    public ScanConnection get() {
        ScanConnection managed = managedConnection.get();
        return handlesAuthentication()
                ? managed
                : managed.withHeaders(baseline -> currentCredentials.get());
    }
}
