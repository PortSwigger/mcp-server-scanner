package com.mcpscanner.automation;

import burp.api.montoya.http.sessions.CookieJar;
import com.mcpscanner.auth.oauth.SignInListener;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class SignedInSessionSeed {

    static final Duration COOKIE_LIFETIME = Duration.ofDays(1);

    private final Supplier<CookieJar> jar;
    private final Consumer<Boolean> optIn;
    private final SignInListener connectSignIns;
    private final Clock clock;

    public SignedInSessionSeed(Supplier<CookieJar> jar, Consumer<Boolean> optIn, SignInListener connectSignIns,
                               Clock clock) {
        this.jar = jar;
        this.optIn = optIn;
        this.connectSignIns = connectSignIns;
        this.clock = clock;
    }

    public SignedInSessionSeeded apply(SignedInSessionCommand command) {
        ZonedDateTime expiry = ZonedDateTime.now(clock).plus(COOKIE_LIFETIME);
        command.cookies().forEach(cookie ->
                jar.get().setCookie(cookie.name(), cookie.value(), cookie.path(), cookie.domain(), expiry));
        if (command.optsIn()) {
            optIn.accept(true);
        }
        return new SignedInSessionSeeded(command.cookies().size(), command.optsIn());
    }

    void beforeConnect(SignedInSessionCommand command, String endpoint) {
        apply(command);
        command.client().map(client -> client.signInFor(URI.create(endpoint))).ifPresent(connectSignIns::signedIn);
    }
}
