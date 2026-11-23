package com.mcpscanner.checks.shared.auth;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.auth.AuthHeaderNames;
import com.mcpscanner.auth.AuthStrategy;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

public final class CredentialVariants implements AuthVariantGenerator {

    static final String GARBAGE_TOKEN = "not_a_real_token_12345";
    static final String GARBAGE_CREDENTIAL = "not_a_real_credential_12345";

    private final Supplier<AuthStrategy> authStrategy;
    private final String canary;

    public CredentialVariants(Supplier<AuthStrategy> authStrategy, String canary) {
        this.authStrategy = authStrategy;
        this.canary = canary;
    }

    @Override
    public List<AuthVariant> variantsFor(HttpRequest seed) {
        List<AuthVariant> variants = new ArrayList<>(List.of(
                noCredentials(),
                authorization("empty-bearer", "Bearer "),
                authorization("garbage-bearer", "Bearer " + GARBAGE_TOKEN),
                authorization("no-scheme", GARBAGE_TOKEN),
                authorization("basic-canary", "Basic " + canary)));
        for (String header : customHeaderNames()) {
            variants.add(header(header, "empty", ""));
            variants.add(header(header, "garbage", GARBAGE_CREDENTIAL));
        }
        return List.copyOf(variants);
    }

    public AuthVariant malformedCredential() {
        return customHeaderNames().stream().findFirst()
                .map(header -> header(header, "garbage", GARBAGE_CREDENTIAL))
                .orElseGet(() -> authorization("garbage-bearer", "Bearer " + GARBAGE_TOKEN));
    }

    public AuthVariant fabricatedCredential() {
        FabricatedCredential fabricated = FabricatedCredential.of(authStrategy.get(), canary);
        return fabricated.customHeader()
                .map(header -> header(header, "fabricated", fabricated.value()))
                .orElseGet(() -> authorization("fabricated-bearer", fabricated.value()));
    }

    public AuthVariant noCredentials() {
        return variant("none", "", UnaryOperator.identity());
    }

    private AuthVariant authorization(String name, String value) {
        return variant(name, value, request -> request.withHeader(AuthHeaderNames.AUTHORIZATION, value));
    }

    private AuthVariant header(String header, String kind, String value) {
        return variant(kind + "-" + header.toLowerCase(Locale.ROOT), value,
                request -> request.withHeader(header, value));
    }

    private AuthVariant variant(String name, String value, UnaryOperator<HttpRequest> operator) {
        return AuthVariant.uncontrolled(VariantFamily.CREDENTIAL, "credential." + name,
                new RequestMutation(value, operator));
    }

    private List<String> customHeaderNames() {
        return CustomCredentialHeaders.of(authStrategy.get());
    }
}
