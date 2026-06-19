package com.mcpscanner.auth.oauth;

import java.time.Instant;

public record AuthState(String subject, Instant expiresAt, boolean valid) {}
