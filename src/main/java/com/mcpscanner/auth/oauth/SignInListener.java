package com.mcpscanner.auth.oauth;

@FunctionalInterface
public interface SignInListener {

    void signedIn(OAuthSignIn signIn);

    default void scopesWidened(OAuthSignIn signIn) {
    }
}
