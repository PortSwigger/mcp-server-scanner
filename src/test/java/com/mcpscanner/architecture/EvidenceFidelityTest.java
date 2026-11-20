package com.mcpscanner.architecture;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import java.util.Set;

import static com.tngtech.archunit.base.DescribedPredicate.describe;
import static com.tngtech.archunit.base.DescribedPredicate.not;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.mcpscanner", importOptions = ImportOption.DoNotIncludeTests.class)
public class EvidenceFidelityTest {

    private static final String RECORDING_SEAM = "com.mcpscanner.http.evidence..";

    private static final Set<String> PAIRS_A_RECEIVED_RESPONSE_OR_NONE = Set.of(
            "com.mcpscanner.http.UpstreamEvidence",
            "com.mcpscanner.checks.shared.session.ScannerSentinelRemoval",
            "com.mcpscanner.scan.request.GeneratedRegistrationCleanupHandler",
            "com.mcpscanner.checks.shared.session.StreamingFallback",
            "com.mcpscanner.checks.shared.stream.StreamOpening",
            "com.mcpscanner.checks.api.WithholdingAfterRateLimit",
            "com.mcpscanner.checks.catalog.outboundrequest.FieldProbes",
            "com.mcpscanner.checks.catalog.ssrffilterbypass.FieldSender",
            "com.mcpscanner.scan.EngineScanDestination",
            "com.mcpscanner.ui.engine.McpOnlyScanMenu");

    private static final DescribedPredicate<JavaMethodCall> BUILDS_OR_ALTERS_A_RESPONSE = describe(
            "builds or alters a Montoya HttpResponse",
            call -> call.getTargetOwner().isEquivalentTo(HttpResponse.class)
                    && (call.getName().equals("httpResponse") || call.getName().startsWith("with")));

    private static final DescribedPredicate<JavaMethodCall> PAIRS_AN_EXCHANGE = describe(
            "pairs a request with a response",
            call -> call.getTargetOwner().isEquivalentTo(HttpRequestResponse.class)
                    && call.getName().equals("httpRequestResponse"));

    private static final DescribedPredicate<JavaClass> ALLOWED_TO_PAIR = describe(
            "re-pairs a response it received, or records an unanswered request",
            javaClass -> PAIRS_A_RECEIVED_RESPONSE_OR_NONE.contains(javaClass.getName().split("\\$")[0]));

    @ArchTest
    static final ArchRule responses_come_only_from_recorded_bytes =
            noClasses().that().resideOutsideOfPackage(RECORDING_SEAM)
                    .should().callMethodWhere(BUILDS_OR_ALTERS_A_RESPONSE)
                    .because("issue evidence is what the target returned: Burp's own exchange or the bytes "
                            + "http/evidence/WireRecord recorded (JDK rendering, socket tap). A response rebuilt "
                            + "from our own status, headers and body is not what went over the wire.");

    @ArchTest
    static final ArchRule exchanges_are_paired_only_by_the_seam_or_from_received_responses =
            noClasses().that().resideOutsideOfPackage(RECORDING_SEAM).and(not(ALLOWED_TO_PAIR))
                    .should().callMethodWhere(PAIRS_AN_EXCHANGE)
                    .because("an exchange is either Burp's own, a WireRecord's evidence(), or an explicitly "
                            + "listed class that re-pairs a response it received (or none) with the request "
                            + "actually sent.");
}
