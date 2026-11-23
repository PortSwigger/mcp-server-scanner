package com.mcpscanner.signedin;

import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.RegisteredClientName;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.shared.oauth.IssuerOrigin;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

public final class BrowserConsentProbes {

    private static final String LOG_PREFIX = "Browser consent check: ";
    private static final String FRESH_NAME_PREFIX = "MCP Scanner consent probe ";
    private static final int FRESH_NAME_SUFFIX_LENGTH = 8;

    private final Function<URI, ProbeClientRegistrar> registrars;
    private final BrowserConsentWalk walk;
    private final McpEventLog eventLog;

    public BrowserConsentProbes(Function<URI, ProbeClientRegistrar> registrars, BrowserConsentWalk walk,
                                McpEventLog eventLog) {
        this.registrars = registrars;
        this.walk = walk;
        this.eventLog = eventLog;
    }

    void run(OAuthSignIn signIn) {
        whyEndpointsLeaveIssuerOrigin(signIn).ifPresentOrElse(
                why -> eventLog.info(LOG_PREFIX + "not run: " + why + ", so the browser's session is not used"),
                () -> runWithRegistrationEndpoint(signIn));
    }

    private static Optional<String> whyEndpointsLeaveIssuerOrigin(OAuthSignIn signIn) {
        return IssuerOrigin.whyEndpointsLeave(signIn.issuer(),
                IssuerOrigin.Endpoint.of("authorization", signIn.authorizationEndpoint()),
                new IssuerOrigin.Endpoint("registration", signIn.registrationEndpoint()));
    }

    private void runWithRegistrationEndpoint(OAuthSignIn signIn) {
        signIn.registrationEndpoint().ifPresentOrElse(
                endpoint -> runRegisteringAt(registrars.apply(endpoint), signIn),
                () -> eventLog.info(LOG_PREFIX + "not run: the authorization server advertises no registration "
                        + "endpoint, so no probe client can be registered"));
    }

    private void runRegisteringAt(ProbeClientRegistrar registrar, OAuthSignIn signIn) {
        try {
            if (sameNameFiredOrUnknown(signIn, registrar)) {
                fired(SignedInProbe.FRESH_NAME, freshName(), signIn, registrar);
            }
        } catch (RuntimeException failure) {
            eventLog.warn(LOG_PREFIX + "stopped: " + failure.getMessage());
        } finally {
            deleteRegisteredClientsEvenWhileUnloading(registrar);
        }
    }

    private void deleteRegisteredClientsEvenWhileUnloading(ProbeClientRegistrar registrar) {
        boolean unloading = Thread.interrupted();
        try {
            eventLog.info(LOG_PREFIX + registrar.deleteRegisteredClients().summary());
        } finally {
            if (unloading) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private boolean sameNameFiredOrUnknown(OAuthSignIn signIn, ProbeClientRegistrar registrar) {
        Optional<String> registeredName = new RegisteredClientName(signIn.clientName()).value();
        if (registeredName.isEmpty()) {
            eventLog.info(LOG_PREFIX + SignedInProbe.SAME_NAME + " not run: " + RegisteredClientName.UNKNOWN);
            return true;
        }
        return fired(SignedInProbe.SAME_NAME, registeredName.get(), signIn, registrar);
    }

    private boolean fired(SignedInProbe probe, String clientName, OAuthSignIn signIn,
                          ProbeClientRegistrar registrar) {
        Optional<BrowserConsentObservation> observation = walk.observe(probe, clientName, signIn, registrar);
        if (Thread.currentThread().isInterrupted()) {
            eventLog.info(LOG_PREFIX + probe + " stopped: the extension is unloading");
            return false;
        }
        if (observation.isEmpty()) {
            eventLog.info(LOG_PREFIX + probe + " not run: the probe client was not registered");
            return false;
        }
        eventLog.info(LOG_PREFIX + probe + outcome(observation.get()));
        return observation.get().codeWithoutInteraction();
    }

    private static String outcome(BrowserConsentObservation observation) {
        if (observation.codeWithoutInteraction()) {
            return " received a code without interaction";
        }
        if (observation.codeTooLateToCount()) {
            return " received a code after " + observation.codeArrivedAfter().orElseThrow().toMillis() + " ms, too "
                    + "late to rule out an approval click, so it is not counted (a slow browser start can cause this)";
        }
        return " received no code before the wait ended (consent asked or not approved)";
    }

    private static String freshName() {
        return FRESH_NAME_PREFIX + UUID.randomUUID().toString().substring(0, FRESH_NAME_SUFFIX_LENGTH);
    }
}
