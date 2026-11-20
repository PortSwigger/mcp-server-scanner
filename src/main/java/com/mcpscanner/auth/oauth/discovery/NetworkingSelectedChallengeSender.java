package com.mcpscanner.auth.oauth.discovery;

import java.net.URI;
import java.util.Optional;
import java.util.function.BooleanSupplier;

final class NetworkingSelectedChallengeSender implements ChallengeSender {

    private final BooleanSupplier useBurpNetworking;
    private final ChallengeSender throughBurp;
    private final ChallengeSender direct;

    NetworkingSelectedChallengeSender(BooleanSupplier useBurpNetworking, ChallengeSender throughBurp,
                                      ChallengeSender direct) {
        this.useBurpNetworking = useBurpNetworking;
        this.throughBurp = throughBurp;
        this.direct = direct;
    }

    @Override
    public Optional<ChallengeResponse> send(URI mcpResource) {
        return selected().send(mcpResource);
    }

    private ChallengeSender selected() {
        return useBurpNetworking.getAsBoolean() ? throughBurp : direct;
    }
}
