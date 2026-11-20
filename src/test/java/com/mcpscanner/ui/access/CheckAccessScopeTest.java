package com.mcpscanner.ui.access;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Stream;

import static com.mcpscanner.access.AccessFixtures.identity;
import static org.assertj.core.api.Assertions.assertThat;

class CheckAccessScopeTest {

    private static final Principal ALICE = identity("alice", PrincipalRole.PRIMARY);

    @Test
    void namesTheConnectAsUserThenEveryComparedUser() {
        assertThat(CheckAccessScope.describe(104, ALICE, users("bob", "carol")))
                .isEqualTo("104 items · alice vs bob, carol + No credential + Fake token");
    }

    @Test
    void countsASingleItemInTheSingular() {
        assertThat(CheckAccessScope.describe(1, ALICE, users("bob"))).isEqualTo("1 item · alice vs bob + No credential + Fake token");
    }

    @Test
    void namesThreeComparedUsersAndCountsTheRest() {
        assertThat(CheckAccessScope.describe(7, ALICE, users("bob", "carol", "dave", "erin", "frank")))
                .isEqualTo("7 items · alice vs bob, carol, dave +2 more + No credential + Fake token");
    }

    @Test
    void namesExactlyThreeComparedUsersWithoutACount() {
        assertThat(CheckAccessScope.describe(7, ALICE, users("bob", "carol", "dave")))
                .isEqualTo("7 items · alice vs bob, carol, dave + No credential + Fake token");
    }

    private static List<Principal> users(String... names) {
        return Stream.of(names).map(name -> identity(name, PrincipalRole.PEER)).toList();
    }
}
