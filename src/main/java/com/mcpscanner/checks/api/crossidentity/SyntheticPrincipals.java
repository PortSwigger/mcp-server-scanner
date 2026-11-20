package com.mcpscanner.checks.api.crossidentity;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.shared.auth.FabricatedCredential;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public final class SyntheticPrincipals {

    private static final int CANARY_LENGTH = 12;

    private final Supplier<AuthStrategy> primaryAuth;
    private final AtomicReference<String> canary = new AtomicReference<>(newCanary());
    private final Principal noCredential = Principal.anonymous();
    private final Principal fakeToken = Principal.fakeToken(this::fabricatedHeaders);

    public SyntheticPrincipals(Supplier<AuthStrategy> primaryAuth) {
        this.primaryAuth = primaryAuth;
    }

    public void renew() {
        canary.set(newCanary());
    }

    public List<Principal> renewed() {
        renew();
        return all();
    }

    public Principal noCredential() {
        return noCredential;
    }

    public Principal fakeToken() {
        return fakeToken;
    }

    public List<Principal> all() {
        return List.of(noCredential, fakeToken);
    }

    private Map<String, String> fabricatedHeaders() {
        return FabricatedCredential.of(primaryAuth.get(), canary.get()).headers();
    }

    private static String newCanary() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, CANARY_LENGTH);
    }
}
