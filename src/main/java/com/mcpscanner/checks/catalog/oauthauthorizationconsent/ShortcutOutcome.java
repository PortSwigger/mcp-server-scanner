package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import java.util.Optional;

record ShortcutOutcome(UnattendedAuthorization authorization, Optional<ConsentFinding> finding) {
}
