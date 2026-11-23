package com.mcpscanner.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import java.net.ServerSocket;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.OnlyIncludeTests.class)
public class TestFixtureHygieneTest {

    @ArchTest
    static final ArchRule test_sockets_never_bind_the_wildcard_address =
            noClasses().should().callConstructor(ServerSocket.class, int.class)
                    .orShould().callConstructor(ServerSocket.class, int.class, int.class)
                    .because("a listener on the wildcard address loses loopback connections to any process that "
                            + "later binds 127.0.0.1 on the same port, which macOS allows, so the test talks to a "
                            + "stranger and fails at random; bind InetAddress.getLoopbackAddress() or use "
                            + "ClosedPort.onLoopback() for a free port.");
}
