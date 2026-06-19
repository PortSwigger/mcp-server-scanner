package com.mcpscanner.auth.oauth;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BrowserLauncherTest {

    @Test
    void desktopLauncherRefusesJavascriptScheme() {
        BrowserLauncher launcher = BrowserLauncher.desktopLauncher();

        assertThatThrownBy(() -> launcher.open(URI.create("javascript:alert(1)")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void desktopLauncherRefusesFileScheme() {
        BrowserLauncher launcher = BrowserLauncher.desktopLauncher();

        assertThatThrownBy(() -> launcher.open(URI.create("file:///etc/passwd")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void desktopLauncherRefusesPlainHttpForRemoteHost() {
        BrowserLauncher launcher = BrowserLauncher.desktopLauncher();

        assertThatThrownBy(() -> launcher.open(URI.create("http://issuer.example.com/authorize")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void desktopLauncherRefusesPrivateRangeUrl() {
        BrowserLauncher launcher = BrowserLauncher.desktopLauncher();

        assertThatThrownBy(() -> launcher.open(URI.create("http://10.0.0.1/authorize")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void validatedLauncherDelegatesValidUrl() {
        AtomicReference<URI> received = new AtomicReference<>();
        BrowserLauncher delegate = received::set;
        BrowserLauncher validated = BrowserLauncher.validated(delegate);

        validated.open(URI.create("https://issuer.example.com/authorize"));

        assertThat(received.get()).isEqualTo(URI.create("https://issuer.example.com/authorize"));
    }

    @Test
    void validatedLauncherBlocksInvalidUrlBeforeDelegation() {
        AtomicReference<URI> received = new AtomicReference<>();
        BrowserLauncher delegate = received::set;
        BrowserLauncher validated = BrowserLauncher.validated(delegate);

        assertThatThrownBy(() -> validated.open(URI.create("javascript:alert(1)")))
                .isInstanceOf(OAuthException.class);
        assertThat(received.get()).isNull();
    }

    @Test
    void browserLauncherRejectsUnsupportedSchemeOnLoopbackHost() {
        AtomicReference<URI> received = new AtomicReference<>();
        BrowserLauncher delegate = received::set;
        BrowserLauncher validated = BrowserLauncher.validated(delegate);

        assertThatThrownBy(() -> validated.open(URI.create("ftp://localhost/callback")))
                .isInstanceOf(OAuthException.class);
        assertThatThrownBy(() -> validated.open(URI.create("javascript://localhost/callback")))
                .isInstanceOf(OAuthException.class);
        assertThat(received.get()).isNull();
    }
}
