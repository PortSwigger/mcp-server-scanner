package com.mcpscanner.auth.oauth;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import java.time.Instant;

public record OAuthTokens(AccessToken accessToken,
                          RefreshToken refreshToken,
                          Instant expiresAt,
                          String subject) {}
