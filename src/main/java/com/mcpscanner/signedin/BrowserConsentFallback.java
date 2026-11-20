package com.mcpscanner.signedin;

import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.auth.oauth.SignInListener;
import com.mcpscanner.config.SignedInConsentSetting;

import java.util.concurrent.Executor;

public final class BrowserConsentFallback implements SignInListener {

    private final SignedInConsentSetting setting;
    private final Executor worker;
    private final BrowserConsentProbes probes;

    public BrowserConsentFallback(SignedInConsentSetting setting, Executor worker, BrowserConsentProbes probes) {
        this.setting = setting;
        this.worker = worker;
        this.probes = probes;
    }

    @Override
    public void signedIn(OAuthSignIn signIn) {
        if (setting.optedIn()) {
            worker.execute(() -> probes.run(signIn));
        }
    }
}
