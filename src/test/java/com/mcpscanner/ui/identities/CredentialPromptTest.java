package com.mcpscanner.ui.identities;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.credentials.CredentialNeed;
import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.swing.JToggleButton;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static com.mcpscanner.ui.identities.IdentitiesHarness.fromEdt;
import static com.mcpscanner.ui.identities.IdentitiesHarness.onEdt;
import static org.assertj.core.api.Assertions.assertThat;

@Timeout(30)
class CredentialPromptTest {

    private static final CredentialNeed BEARER_REFUSAL =
            new CredentialNeed.ServerRefused("The server needs credentials and advertises no OAuth sign-in", true);
    private static final CredentialNeed BASIC_REFUSAL =
            new CredentialNeed.ServerRefused("The server challenges with Basic, not OAuth", false);

    private final IdentitiesHarness harness = new IdentitiesHarness();
    private final AtomicInteger connects = new AtomicInteger();
    private final AtomicInteger oauthOpened = new AtomicInteger();
    private final AtomicInteger primaryOpened = new AtomicInteger();
    private CredentialPrompt prompt;

    @AfterEach
    void tearDown() {
        harness.close();
    }

    @Test
    void staysHiddenUntilSomethingIsNeeded() throws Exception {
        open();

        onEdt(() -> prompt.show(Optional.empty()));

        assertThat(fromEdt(prompt::isVisible)).isFalse();
    }

    @Test
    void aBearerRefusalIsOneRowWithAShortTokenFieldAndNoKindChoice() throws Exception {
        open();

        onEdt(() -> prompt.show(Optional.of(BEARER_REFUSAL)));

        assertThat(fromEdt(prompt::titleText)).isEqualTo("The server needs credentials for User 1.");
        String tooltip = fromEdt(prompt::getToolTipText);
        assertThat(tooltip).contains("advertises no OAuth sign-in", "saved to User 1");
        assertThat(fromEdt(() -> prompt.tokenField().isVisible())).isTrue();
        assertThat(fromEdt(() -> prompt.tokenField().getPreferredSize().width))
                .isEqualTo(CredentialPrompt.TOKEN_WIDTH);
        assertThat(fromEdt(() -> prompt.saveButton().isVisible())).isTrue();
        assertThat(fromEdt(() -> prompt.otherCredentialsLink().isVisible())).isTrue();
        assertThat(fromEdt(() -> SwingTree.descendants(prompt))).noneMatch(component ->
                component instanceof JToggleButton toggle && "Custom headers".equals(toggle.getText()));
        assertThat(fromEdt(prompt::rowsInUse)).isEqualTo(1);
    }

    @Test
    void savingATokenWritesItToThePrimaryUserAndConnects() throws Exception {
        open();
        onEdt(() -> prompt.show(Optional.of(BEARER_REFUSAL)));

        onEdt(() -> prompt.tokenField().setValue("user-one-token"));
        onEdt(() -> prompt.saveButton().doClick());

        assertThat(harness.userOne().authKind()).isEqualTo(IdentityAuthKind.BEARER);
        assertThat(harness.registry.credential(harness.userOne().id())).get()
                .satisfies(credential -> assertThat(credential.headers())
                        .containsEntry("Authorization", "Bearer user-one-token"));
        assertThat(connects).hasValue(1);
        assertThat(fromEdt(prompt::isVisible)).isFalse();
        assertThat(harness.config.identitiesJson()).doesNotContain("user-one-token");
    }

    @Test
    void aBlankTokenIsRefusedInPlaceWithoutConnecting() throws Exception {
        open();
        onEdt(() -> prompt.show(Optional.of(BEARER_REFUSAL)));

        onEdt(() -> prompt.saveButton().doClick());

        assertThat(fromEdt(prompt::titleText)).isEqualTo("Enter the bearer token");
        assertThat(connects).hasValue(0);
        assertThat(fromEdt(prompt::isVisible)).isTrue();
    }

    @Test
    void otherCredentialsOpensThePrimaryUserInUsers() throws Exception {
        open();
        onEdt(() -> prompt.show(Optional.of(BEARER_REFUSAL)));

        onEdt(() -> prompt.otherCredentialsLink().activate());

        assertThat(primaryOpened).hasValue(1);
    }

    @Test
    void aNonBearerChallengeOffersNoTokenFieldOnlyAddCredentials() throws Exception {
        open();

        onEdt(() -> prompt.show(Optional.of(BASIC_REFUSAL)));

        assertThat(fromEdt(() -> prompt.tokenField().isVisible())).isFalse();
        assertThat(fromEdt(() -> prompt.actionButton().getText())).isEqualTo("Add credentials for User 1");
        onEdt(() -> prompt.actionButton().doClick());
        assertThat(primaryOpened).hasValue(1);
    }

    @Test
    void anIncompleteOAuthSignInOpensTheOAuthClient() throws Exception {
        open();

        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.OAuthSignInIncomplete("Client ID is required"))));

        assertThat(fromEdt(prompt::titleText)).isEqualTo("The OAuth client is incomplete: Client ID is required.");
        assertThat(fromEdt(() -> prompt.tokenField().isVisible())).isFalse();
        assertThat(fromEdt(() -> prompt.actionButton().getText())).isEqualTo("Open OAuth client");
        onEdt(() -> prompt.actionButton().doClick());
        assertThat(oauthOpened).hasValue(1);
    }

    @Test
    void aMissingBearerTokenIsEnteredInlineButMissingHeadersOpenUsers() throws Exception {
        open();

        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.MissingCredential(IdentityAuthKind.BEARER,
                "Enter a bearer token for User 1"))));
        assertThat(fromEdt(prompt::titleText)).isEqualTo("User 1 is set to Bearer token but has none.");
        assertThat(fromEdt(() -> prompt.tokenField().isVisible())).isTrue();

        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.MissingCredential(IdentityAuthKind.CUSTOM_HEADERS,
                "Enter the header values for User 1"))));
        assertThat(fromEdt(() -> prompt.tokenField().isVisible())).isFalse();
        onEdt(() -> prompt.actionButton().doClick());
        assertThat(primaryOpened).hasValue(1);
    }

    @Test
    void refusedToolCallsOpenThePrimaryUserAndCanBeDismissedUntilTheyStop() throws Exception {
        open();
        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.ToolCallsRefused(3))));

        assertThat(fromEdt(prompt::titleText)).isEqualTo("The server refused 3 tool calls: User 1 has no credentials.");
        assertThat(fromEdt(() -> prompt.tokenField().isVisible())).isFalse();
        onEdt(() -> prompt.actionButton().doClick());
        assertThat(primaryOpened).hasValue(1);

        onEdt(() -> prompt.dismissButton().doClick());
        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.ToolCallsRefused(4))));
        assertThat(fromEdt(prompt::isVisible)).isFalse();

        onEdt(() -> prompt.show(Optional.empty()));
        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.ToolCallsRefused(1))));
        assertThat(fromEdt(prompt::isVisible)).isTrue();
    }

    @Test
    void withoutComparedUsersRefusedToolCallsAreNotExplainedInScanTerms() throws Exception {
        onEdt(() -> prompt = new UsersPanel(harness.services, GrantCredentialForms.NONE, () -> { },
                UsersMode.PRIMARY_ONLY).credentialPrompt(actions()));

        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.ToolCallsRefused(3))));

        String tooltip = fromEdt(prompt::getToolTipText);
        assertThat(tooltip).isEqualTo("Connecting was allowed anonymously, so requests as "
                + "User 1 only reach what an anonymous user can.");
    }

    @Test
    void moreRefusedCallsOnlyUpdateTheCount() throws Exception {
        open();
        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.ToolCallsRefused(3))));

        onEdt(() -> prompt.show(Optional.of(new CredentialNeed.ToolCallsRefused(4))));

        assertThat(fromEdt(prompt::titleText)).isEqualTo("The server refused 4 tool calls: User 1 has no credentials.");
    }

    @Test
    void savingWhileTheUserAlreadyHoldsATokenReplacesIt() throws Exception {
        harness.registry.update(harness.userOne().withAuthKind(IdentityAuthKind.BEARER));
        harness.registry.setCredential(harness.userOne().id(), new BearerTokenAuthStrategy("old"));
        open();
        onEdt(() -> prompt.show(Optional.of(BEARER_REFUSAL)));

        onEdt(() -> prompt.tokenField().setValue("new"));
        onEdt(() -> prompt.saveButton().doClick());

        assertThat(harness.registry.credential(harness.userOne().id())).get()
                .satisfies(credential -> assertThat(credential.headers())
                        .containsEntry("Authorization", "Bearer new"));
    }

    private void open() throws Exception {
        onEdt(() -> prompt = new CredentialPrompt(harness.services, actions()));
    }

    private CredentialPrompt.Actions actions() {
        return new CredentialPrompt.Actions() {
            @Override
            public void connect() {
                connects.incrementAndGet();
            }

            @Override
            public void openOAuthClient() {
                oauthOpened.incrementAndGet();
            }

            @Override
            public void openPrimaryUser() {
                primaryOpened.incrementAndGet();
            }
        };
    }
}
