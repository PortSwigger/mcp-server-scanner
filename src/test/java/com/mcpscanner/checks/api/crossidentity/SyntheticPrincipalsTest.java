package com.mcpscanner.checks.api.crossidentity;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SyntheticPrincipalsTest {

    @Test
    void listsNoCredentialThenFakeTokenAsLowerPrivilegePrincipals() {
        SyntheticPrincipals synthetic = new SyntheticPrincipals(() -> new BearerTokenAuthStrategy("t"));

        assertThat(synthetic.all()).extracting(Principal::id)
                .containsExactly(Principal.ANONYMOUS_ID, Principal.FAKE_TOKEN_ID);
        assertThat(synthetic.all()).extracting(Principal::role).containsOnly(PrincipalRole.LOWER);
        assertThat(synthetic.noCredential().credentialHeaders().get()).isEmpty();
    }

    @Test
    void fakeTokenCarriesAnInvalidBearerTokenWhenThePrimaryUsesBearerAuth() {
        SyntheticPrincipals synthetic = new SyntheticPrincipals(() -> new BearerTokenAuthStrategy("t"));

        assertThat(synthetic.fakeToken().credentialHeaders().get())
                .hasEntrySatisfying("Authorization", value -> assertThat(value).startsWith("Bearer invalid_"));
    }

    @Test
    void fakeTokenUsesThePrimarysCustomCredentialHeader() {
        SyntheticPrincipals synthetic = new SyntheticPrincipals(
                () -> new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "real")));

        assertThat(synthetic.fakeToken().credentialHeaders().get())
                .hasEntrySatisfying("X-Api-Key", value -> assertThat(value).startsWith("invalid_"))
                .doesNotContainValue("real");
    }

    @Test
    void renewingIssuesADifferentFakeToken() {
        SyntheticPrincipals synthetic = new SyntheticPrincipals(() -> new BearerTokenAuthStrategy("t"));
        Map<String, String> before = synthetic.fakeToken().credentialHeaders().get();

        synthetic.renew();

        assertThat(synthetic.fakeToken().credentialHeaders().get()).isNotEqualTo(before);
    }
}
