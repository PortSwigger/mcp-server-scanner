package com.mcpscanner.ui.identities;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.SignedInTokens;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.credentials.CredentialRequirement;
import com.mcpscanner.identity.credentials.SignInStatus;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;
import com.mcpscanner.identity.discovery.IdentityListing;
import com.mcpscanner.ui.widgets.Plurals;

import java.util.Optional;

final class IdentityStatusText {

    static final String READY_MARK = "● ";
    static final String WARNING_MARK = "▲ ";
    static final String NOT_DISCOVERED = "Not discovered yet";
    static final String CREDENTIAL_CHANGED = "Credential changed - press " + DiscoverButton.LABEL;
    static final String DISCOVERING = "Discovering…";
    private static final String NO_CREDENTIALS = "No credentials";

    private final IdentityUiServices services;

    IdentityStatusText(IdentityUiServices services) {
        this.services = services;
    }

    String of(IdentityRow row) {
        return row.identity().map(this::ofMember).orElse(NO_CREDENTIALS);
    }

    String session(Identity identity) {
        if (services.registry().isPrimary(identity.id())) {
            return connectAsSession(identity.name());
        }
        if (credentialChanged(identity)) {
            return CREDENTIAL_CHANGED;
        }
        return outcome(identity).map(IdentityStatusText::describeSession)
                .orElseGet(() -> services.isConnected() ? NOT_DISCOVERED : "Discovered after Connect");
    }

    String signIn(Identity identity) {
        SignInStatus status = services.signIns().status(identity.id());
        return switch (status.state()) {
            case NEEDS_CREDENTIALS -> "Not signed in";
            case QUEUED -> "Queued for sign-in";
            case SIGNING_IN -> "Signing in…";
            case READY -> READY_MARK + "Signed in" + account(identity).map(" as "::concat).orElse("");
            case FAILED -> WARNING_MARK + "Sign-in failed" + status.reason().map(reason -> ": " + reason).orElse("");
        };
    }

    private String connectAsSession(String name) {
        return services.isConnected() ? "Connected. Connect, discovery and Scan run as " + name + "."
                : "Not connected. Connect, discovery and Scan run as " + name + " once connected.";
    }

    private Optional<String> account(Identity identity) {
        return services.registry().credential(identity.id()).flatMap(AuthStrategy::signedInTokens)
                .flatMap(SignedInTokens::subject);
    }

    private String ofMember(Identity identity) {
        boolean connectAs = services.registry().isPrimary(identity.id());
        if (connectAs && services.refusals().refusedWithoutCredentials()) {
            return WARNING_MARK + "No token";
        }
        if (connectAs && services.isConnected()) {
            return READY_MARK + "Connected";
        }
        if (services.registry().credential(identity.id()).isPresent()) {
            return describeDiscovery(identity);
        }
        return describeMissing(identity);
    }

    private String describeDiscovery(Identity identity) {
        if (credentialChanged(identity)) {
            return WARNING_MARK + CREDENTIAL_CHANGED;
        }
        return outcome(identity).map(IdentityStatusText::describeOutcome)
                .orElseGet(() -> services.isConnected() ? NOT_DISCOVERED : READY_MARK + "Ready");
    }

    private boolean credentialChanged(Identity identity) {
        return services.discovery().credentialChangedSinceDiscovery(identity.id());
    }

    private String describeMissing(Identity identity) {
        CredentialRequirement requirement = services.credentials().requirement(identity.id());
        if (requirement instanceof CredentialRequirement.Unavailable unavailable) {
            return WARNING_MARK + unavailable.reason();
        }
        if (requirement instanceof CredentialRequirement.NoCredentials) {
            return NO_CREDENTIALS;
        }
        if (requirement instanceof CredentialRequirement.GrantAtConnect) {
            return "Gets a token at Connect";
        }
        if (requirement instanceof CredentialRequirement.BrowserSignInRequired) {
            return describePendingSignIn(identity);
        }
        if (requirement instanceof CredentialRequirement.HeaderValuesRequired) {
            return WARNING_MARK + "Header values needed";
        }
        return WARNING_MARK + "Token needed";
    }

    private String describePendingSignIn(Identity identity) {
        String signIn = signIn(identity);
        return signIn.equals("Not signed in") ? WARNING_MARK + "Sign in" : signIn;
    }

    private Optional<DiscoveryOutcome> outcome(Identity identity) {
        return services.listings().outcome(identity.id());
    }

    private static String describeOutcome(DiscoveryOutcome outcome) {
        if (outcome instanceof DiscoveryOutcome.Listed listed) {
            return READY_MARK + "Listed " + counts(listed.listing());
        }
        if (outcome instanceof DiscoveryOutcome.Failed failed) {
            return WARNING_MARK + "Failed: " + failed.reason();
        }
        return DISCOVERING;
    }

    private static String describeSession(DiscoveryOutcome outcome) {
        if (outcome instanceof DiscoveryOutcome.Listed listed) {
            return "Own MCP session: " + counts(listed.listing()) + " listed";
        }
        if (outcome instanceof DiscoveryOutcome.Failed failed) {
            return "Discovery failed: " + failed.reason();
        }
        return "Discovering with its own MCP session…";
    }

    private static String counts(IdentityListing listing) {
        return Plurals.count(listing.toolNames().size(), "tool") + ", "
                + Plurals.count(listing.resourceUris().size(), "resource");
    }
}
