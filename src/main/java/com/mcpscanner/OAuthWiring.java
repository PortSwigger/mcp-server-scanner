package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import com.mcpscanner.auth.grants.EnterpriseIdentityProviderRegistry;
import com.mcpscanner.auth.grants.OptionalGrantAuthFactory;
import com.mcpscanner.auth.oauth.ActiveCallbackListeners;
import com.mcpscanner.auth.oauth.BrowserLauncher;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.auth.oauth.safety.BoundedHostResolver;
import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.HostResolver;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationConfirmer;
import com.mcpscanner.logging.McpEventLog;

import java.time.Clock;
import java.util.List;

record OAuthWiring(BoundedHostResolver dnsResolver,
                   DefaultSuspiciousDestinationGate authorizationGate,
                   ActiveCallbackListeners callbackListeners,
                   OAuthAuthorizationFlow authorizationFlow,
                   OAuthAuthorizationFlow identitySignInFlow,
                   OAuthMetadataDiscoverer discoverer,
                   OptionalGrantAuthFactory optionalGrants) {

    static OAuthWiring create(MontoyaApi api, ExtensionFoundation foundation, Http http) {
        McpEventLog eventLog = foundation.eventLog();
        BoundedHostResolver dnsResolver = HostResolver.defaultResolver();
        DefaultSuspiciousDestinationGate gate = DefaultSuspiciousDestinationGate.prompting(
                SuspiciousDestinationConfirmer.swing(eventLog, () -> api.userInterface().swingUtils().suiteFrame()),
                dnsResolver, eventLog);
        ActiveCallbackListeners callbackListeners = new ActiveCallbackListeners();
        return new OAuthWiring(dnsResolver, gate, callbackListeners,
                authorizationFlow(api, foundation, http, gate, callbackListeners, BrowserLauncher.desktop(eventLog)),
                authorizationFlow(api, foundation, http, gate, callbackListeners,
                        BrowserLauncher.promptingLogin(BrowserLauncher.desktop(eventLog))),
                OAuthMetadataDiscoverer.defaultInstance(http, eventLog, gate, foundation.configStore()::useBurpNetworking),
                new OptionalGrantAuthFactory(http, gate, EnterpriseIdentityProviderRegistry.load(),
                        Clock.systemUTC()));
    }

    private static OAuthAuthorizationFlow authorizationFlow(MontoyaApi api, ExtensionFoundation foundation, Http http,
                                                            DefaultSuspiciousDestinationGate gate,
                                                            ActiveCallbackListeners callbackListeners,
                                                            BrowserLauncher browser) {
        McpEventLog eventLog = foundation.eventLog();
        return new OAuthAuthorizationFlow(callbackListeners,
                BrowserLauncher.validated(browser, gate),
                Clock.systemUTC(), gate, eventLog, http, foundation.identityProvider());
    }

    List<Runnable> sessionResets() {
        return List.of(authorizationGate::reset);
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("OAuth callback listeners", callbackListeners::closeAll);
        shutdown.add("DNS resolver", dnsResolver::close);
    }
}
