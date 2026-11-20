package com.mcpscanner.ui.access;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.SyntheticLabel;

import java.util.Optional;

sealed interface AccessColumn {

    String title();

    default Optional<String> note() {
        return Optional.empty();
    }

    record Item() implements AccessColumn {
        @Override
        public String title() {
            return "Item";
        }
    }

    record Identity(Principal principal, boolean withoutIds) implements AccessColumn {

        static final String WITHOUT_IDS_MARK = " ⚠";
        static final String WITHOUT_IDS_NOTE = "No IDs collected for this user, so other users' IDs look private. "
                + "Give this user some data.";

        Identity(Principal principal) {
            this(principal, false);
        }

        @Override
        public String title() {
            return PrincipalLabels.column(principal) + (withoutIds ? WITHOUT_IDS_MARK : "");
        }

        @Override
        public Optional<String> note() {
            return withoutIds ? Optional.of(WITHOUT_IDS_NOTE) : Optional.empty();
        }
    }

    sealed interface Synthetic extends AccessColumn {

        SyntheticLabel label();

        @Override
        default String title() {
            return label().label();
        }

        default String principalId() {
            return label().principalId();
        }

        default String described() {
            return label().described();
        }

        default String withThe() {
            return label().withThe();
        }
    }

    record Anonymous() implements Synthetic {
        @Override
        public SyntheticLabel label() {
            return SyntheticLabel.NO_CREDENTIAL;
        }
    }

    record FakeToken() implements Synthetic {
        @Override
        public SyntheticLabel label() {
            return SyntheticLabel.FAKE_TOKEN;
        }
    }

    record Expectation() implements AccessColumn {
        @Override
        public String title() {
            return "Who should reach it";
        }
    }
}
