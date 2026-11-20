package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.credentials.CredentialNeed;
import com.mcpscanner.ui.widgets.Plurals;

record CredentialPromptText(String title, String detail) {

    static CredentialPromptText of(CredentialNeed need, String user, UsersMode mode) {
        if (need instanceof CredentialNeed.ServerRefused refused) {
            return new CredentialPromptText("The server needs credentials for " + user + ".",
                    sentence(refused.answer()) + " What you enter is saved to " + user + ", then Connect runs again.");
        }
        if (need instanceof CredentialNeed.OAuthSignInIncomplete incomplete) {
            return new CredentialPromptText("The OAuth client is incomplete: " + sentence(incomplete.problem()),
                    "The server uses OAuth. Complete the OAuth client in the Client tab, then Connect again.");
        }
        if (need instanceof CredentialNeed.MissingCredential missing) {
            return new CredentialPromptText(missingTitle(missing, user),
                    "What you enter is saved to " + user + ", then Connect runs.");
        }
        CredentialNeed.ToolCallsRefused refused = (CredentialNeed.ToolCallsRefused) need;
        return new CredentialPromptText("The server refused " + Plurals.count(refused.count(), "tool call") + ": "
                + user + " has no credentials.", "Connecting was allowed anonymously, so "
                + mode.anonymousReach(user) + " what an anonymous user can.");
    }

    static boolean takesTokenInline(CredentialNeed need) {
        return need instanceof CredentialNeed.ServerRefused refused && refused.bearerExpected()
                || need instanceof CredentialNeed.MissingCredential missing
                && missing.kind() == IdentityAuthKind.BEARER;
    }

    static String action(CredentialNeed need, String user) {
        return need instanceof CredentialNeed.OAuthSignInIncomplete ? "Open OAuth client"
                : "Add credentials for " + user;
    }

    private static String missingTitle(CredentialNeed.MissingCredential missing, String user) {
        return switch (missing.kind()) {
            case BEARER -> user + " is set to Bearer token but has none.";
            case CUSTOM_HEADERS -> user + " is set to Custom headers but has no values.";
            default -> sentence(missing.problem());
        };
    }

    private static String sentence(String text) {
        String trimmed = text.strip();
        return trimmed.endsWith(".") ? trimmed : trimmed + ".";
    }
}
