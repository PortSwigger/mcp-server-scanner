package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.auth.oauth.BrowserLauncher;
import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.auth.oauth.SignInListener;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.config.SignedInConsentSetting;
import com.mcpscanner.signedin.BrowserConsentFallback;
import com.mcpscanner.signedin.BrowserConsentObservations;
import com.mcpscanner.signedin.BrowserConsentProbes;
import com.mcpscanner.signedin.BrowserConsentWalk;
import com.mcpscanner.signedin.BurpSignedInConsent;
import com.mcpscanner.signedin.ConnectSignIns;
import com.mcpscanner.signedin.CookieJarSessions;
import com.mcpscanner.signedin.ProxyHistoryCookieOrigins;
import com.mcpscanner.signedin.ProbeWorker;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

record SignedInConsentWiring(SignedInConsentSetting setting,
                             BrowserConsentObservations browserObservations,
                             SignedInConsent consent,
                             SignInListener connectSignIns,
                             ProbeWorker browserProbeWorker) {

    private static final Duration PROBE_CLEANUP_WAIT = Duration.ofSeconds(10);

    static SignedInConsentWiring create(MontoyaApi api, ExtensionFoundation foundation, ConnectionWiring connection,
                                        OAuthWiring oauth) {
        SignedInConsentSetting setting = new SignedInConsentSetting(foundation.configStore());
        BrowserConsentObservations observations = new BrowserConsentObservations();
        ConnectSignIns signIns = new ConnectSignIns();
        ProbeWorker browserProbeWorker = ProbeWorker.daemon(foundation.eventLog());
        listenToConnectSignIns(foundation, connection, oauth, signIns,
                browserConsentFallback(api, foundation, oauth, setting, observations, browserProbeWorker));
        connection.resetOnDisconnect(List.of(observations::clear));
        foundation.configStore().addEndpointChangeListener(observations::clear);
        CookieJarSessions cookieJar = new CookieJarSessions(() -> api.http().cookieJar().cookies(),
                new ProxyHistoryCookieOrigins(filter -> api.proxy().history(filter)), Clock.systemUTC());
        return new SignedInConsentWiring(setting, observations,
                new BurpSignedInConsent(setting, signIns, cookieJar, observations),
                signIns, browserProbeWorker);
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("Browser consent check", () -> browserProbeWorker.stop(PROBE_CLEANUP_WAIT));
    }

    private static void listenToConnectSignIns(ExtensionFoundation foundation, ConnectionWiring connection,
                                               OAuthWiring oauth, ConnectSignIns signIns,
                                               BrowserConsentFallback browserFallback) {
        oauth.authorizationFlow().addSignInListener(new BothSignInListeners(signIns, browserFallback));
        connection.clientManager().addConnectAttemptListener(signIns::connectAttemptStarted);
        connection.clientManager().addConnectListener(signIns::connected);
        connection.resetOnDisconnect(List.of(signIns::disconnected));
        foundation.configStore().addEndpointChangeListener(signIns::forget);
    }

    private static BrowserConsentFallback browserConsentFallback(MontoyaApi api, ExtensionFoundation foundation,
                                                                 OAuthWiring oauth, SignedInConsentSetting setting,
                                                                 BrowserConsentObservations observations,
                                                                 ProbeWorker worker) {
        BrowserLauncher browser = BrowserLauncher.validated(BrowserLauncher.desktop(foundation.eventLog()),
                oauth.authorizationGate());
        BrowserConsentWalk walk = new BrowserConsentWalk(oauth.callbackListeners(), browser, Clock.systemUTC(),
                BrowserConsentWalk.CODE_WAIT, observations);
        BrowserConsentProbes probes = new BrowserConsentProbes(
                endpoint -> new ProbeClientRegistrar(new OAuthHttp(api.http()), endpoint), walk,
                foundation.eventLog());
        return new BrowserConsentFallback(setting, worker, probes);
    }

    private record BothSignInListeners(SignInListener first, SignInListener second) implements SignInListener {

        @Override
        public void signedIn(OAuthSignIn signIn) {
            first.signedIn(signIn);
            second.signedIn(signIn);
        }

        @Override
        public void scopesWidened(OAuthSignIn signIn) {
            first.scopesWidened(signIn);
            second.scopesWidened(signIn);
        }
    }
}
