package com.mcpscanner.checks.catalog.filetraversal;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.catalog.filetraversal.SimulatedFileTool.Policy;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.testutil.BurpArgumentPoint;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class FileTraversalCheckTest {

    private static final String MISSING = "mcpscan-0011223344";
    private static final String ROOT_FILE = SimulatedFileTool.ROOT + "/readme.txt";
    private final McpEventLog eventLog = new McpEventLog(null);
    private final FileTraversalCheck check = new FileTraversalCheck(() -> MISSING, Optional::empty,
            BurpNativeJsonRpcFields.ABSENT, eventLog);
    private final FileTraversalCheck besideBurpNativeFields = new FileTraversalCheck(() -> MISSING, Optional::empty,
            BurpNativeJsonRpcFields.PRESENT, eventLog);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void declaresAnInsertionPointCheckThatNeedsAReply() {
        assertThat(check.descriptor().id()).isEqualTo("file-traversal");
        assertThat(check.descriptor().kind()).isEqualTo(CheckKind.INSERTION_POINT);
        assertThat(check.descriptor().cwes()).extracting(cwe -> cwe.id()).containsExactly(22);
        assertThat(check.requiresReply()).isTrue();
    }

    @Test
    void reportsAnUnconfinedReaderAsATentativeArbitraryHostFileRead() {
        List<AuditIssue> issues = audit(Policy.UNRESTRICTED, "readme.txt");

        assertThat(issues).extracting(AuditIssue::name).doesNotContain(FindingKind.FILE_READ.issueName());
        AuditIssue fileRead = issueNamed(issues, FindingKind.HOST_FILE_READ);
        assertThat(fileRead.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(fileRead.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(fileRead.detail()).contains("tools/call read_file", "params.arguments.path", MISSING);
        assertThat(fileRead.requestResponses()).hasSizeGreaterThanOrEqualTo(2);
        assertThat(fileRead.requestResponses()).anySatisfy(exchange ->
                assertThat(exchange.responseMarkers()).isNotEmpty());
    }

    @Test
    void namesAnAbsolutePathReadAnArbitraryHostFileReadRatherThanTraversal() {
        List<AuditIssue> issues = audit(Policy.ABSOLUTE_PATHS_ONLY, "readme.txt");

        assertThat(issues).extracting(AuditIssue::name)
                .contains(FindingKind.HOST_FILE_READ.issueName())
                .doesNotContain(FindingKind.FILE_READ.issueName());
        assertThat(FindingKind.HOST_FILE_READ.issueName()).isEqualTo("MCP arbitrary host file read");
        assertThat(issueNamed(issues, FindingKind.HOST_FILE_READ).confidence())
                .isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void aLiteralGitPathRejectedOnlyByATransientErrorIsNotARestrictedPathBypass() {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.CASE_INSENSITIVE_FILESYSTEM)
                .rejectingOnceWithATransientError(".git/config");

        assertThat(audit(tool, "notes.md")).extracting(AuditIssue::name)
                .doesNotContain(FindingKind.RESTRICTED_PATH_BYPASS.issueName())
                .contains(FindingKind.REPOSITORY_METADATA_READ.issueName());
    }

    @Test
    void staysSilentOnAContainedReader() {
        assertThat(audit(Policy.CONTAINED, "readme.txt")).isEmpty();
    }

    @Test
    void reportsAnEncodedEscapeAfterALiteralRejectionAsAFilterBypass() {
        List<AuditIssue> issues = audit(Policy.DECODE_AFTER_CHECK, "readme.txt");

        AuditIssue bypass = issueNamed(issues, FindingKind.FILTER_BYPASS);
        assertThat(bypass.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(bypass.detail()).contains("Rejected literal path: " + "../".repeat(16) + "etc/passwd");
    }

    @Test
    void reportsAPrefixSiblingBoundaryWithoutClaimingContent() {
        List<AuditIssue> issues = audit(Policy.PREFIX_MATCH, "readme.txt");

        assertThat(issues).extracting(AuditIssue::name)
                .contains(FindingKind.ROOT_BOUNDARY_BYPASS.issueName())
                .doesNotContain(FindingKind.FILE_READ.issueName(), FindingKind.FILTER_BYPASS.issueName());
        assertThat(issueNamed(issues, FindingKind.ROOT_BOUNDARY_BYPASS).detail())
                .contains("/srv/workspace_" + MISSING + "/missing");
    }

    @Test
    void staysSilentWhenTheMissingFileControlReturnsTheSameContent() {
        assertThat(audit(Policy.ALWAYS_PASSWD, "readme.txt")).isEmpty();
    }

    @Test
    void staysSilentOnAToolThatAnswersAboutTheFileRatherThanReadingIt() {
        assertThat(audit(Policy.ANSWERS_ABOUT_THE_TOPIC, "readme.txt")).isEmpty();
    }

    @Test
    void staysSilentOnTheBoundaryWhenTheServerMasksDenialsAsMissingFiles() {
        assertThat(audit(Policy.MASKS_DENIAL_AS_MISSING, "readme.txt")).extracting(AuditIssue::name)
                .doesNotContain(FindingKind.ROOT_BOUNDARY_BYPASS.issueName());
    }

    @Test
    void reportsALeakedPasswdPrefixAsPartialDisclosure() {
        List<AuditIssue> issues = audit(Policy.PARSE_ERROR_LEAK, "readme.txt");

        assertThat(issues).extracting(AuditIssue::name).containsExactly(
                FindingKind.PARTIAL_FILE_DISCLOSURE.issueName());
    }

    @Test
    void reportsACaseVariantThatPassesACaseSensitiveRestriction() {
        List<AuditIssue> issues = audit(Policy.CASE_INSENSITIVE_ACL, "notes.md");

        assertThat(issues).extracting(AuditIssue::name).containsExactly(
                FindingKind.RESTRICTED_PATH_BYPASS.issueName());
    }

    @Test
    void reportsAnUnrestrictedRepositoryConfigOnlyAsInformation() {
        assertThat(issueNamed(audit(Policy.CASE_INSENSITIVE_FILESYSTEM, "readme.txt"),
                FindingKind.REPOSITORY_METADATA_READ).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void stopsAtTheFirstConfirmedReadOnAVulnerableField() {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.UNRESTRICTED);
        PathArgumentInsertionPoint point = new PathArgumentInsertionPoint("readme.txt");

        check.audit(point.base(), point, tool.http());

        assertThat(tool.sent()).hasSizeLessThanOrEqualTo(5);
    }

    @Test
    void sendsTheWholeListOnACleanField() {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.CONTAINED);
        PathArgumentInsertionPoint point = new PathArgumentInsertionPoint("readme.txt");

        check.audit(point.base(), point, tool.http());

        assertThat(tool.sent()).hasSizeGreaterThanOrEqualTo(TraversalPayloads.forBaseValue("readme.txt").size());
    }

    @Test
    void findsTheNulBypassWhenTheBaseValueItselfNamesPasswd() {
        assertThat(audit(Policy.EXTENSION_ALLOWLIST_TRUNCATING_AT_NUL, "/workspace/passwd.txt"))
                .extracting(AuditIssue::name).contains(FindingKind.FILTER_BYPASS.issueName());
    }

    @Test
    void reportsAMixedSeparatorEscapeThroughASingleDotDotSlashStrip() {
        assertThat(issueNamed(audit(Policy.STRIPS_DOT_DOT_SLASH_AFTER_COLLAPSING_SLASHES, "readme.txt"),
                FindingKind.FILE_READ).detail()).contains("..././..././");
    }

    @Test
    void reportsAMixedBackslashEscapeThroughASingleDotDotStripOnWindows() {
        assertThat(issueNamed(audit(Policy.WINDOWS_STRIPS_DOT_DOT_ONCE, "readme.txt"),
                FindingKind.FILE_READ).detail()).contains("...\\.\\\\...\\.\\\\");
    }

    @Test
    void reportsADoubleEncodedBackslashEscapeOnAWindowsHostAsAFilterBypass() {
        AuditIssue bypass = issueNamed(audit(Policy.WINDOWS_DOUBLE_DECODING, "readme.txt"), FindingKind.FILTER_BYPASS);

        assertThat(bypass.detail()).contains("%252e%252e%255c", "The field rejected the literal path "
                + "..\\".repeat(16) + "windows\\win.ini");
    }

    @Test
    void reportsARootRelativeWindowsPathPastADriveLetterFilter() {
        assertThat(issueNamed(audit(Policy.WINDOWS_DRIVE_LETTER_FILTER, "readme.txt"),
                FindingKind.HOST_FILE_READ).detail()).contains("\\windows\\win.ini returned");
    }

    @Test
    void staysSilentOnACaseSensitiveFilesystemBehindACaseSensitiveGitDenylist() {
        assertThat(audit(Policy.CASE_SENSITIVE_GIT_DENYLIST_ON_A_CASE_SENSITIVE_FILESYSTEM, "notes.md")).isEmpty();
    }

    @Test
    void reportsANulTerminatedEscapeThroughAnExtensionAllowlistAsAFilterBypass() {
        AuditIssue bypass = issueNamed(audit(Policy.EXTENSION_ALLOWLIST_TRUNCATING_AT_NUL, "readme.txt"),
                FindingKind.FILTER_BYPASS);

        assertThat(bypass.detail()).contains("etc/passwd%00readme.txt",
                "The field rejected the literal path " + "../".repeat(16) + "etc/passwd", "NUL-terminated");
    }

    @Test
    void staysSilentOnAnExtensionAllowlistThatKeepsTheNul() {
        assertThat(audit(Policy.EXTENSION_ALLOWLIST, "readme.txt")).isEmpty();
    }

    @Test
    void reportsAnEncodedBackslashEscapeOnAWindowsHostAsAFilterBypass() {
        AuditIssue bypass = issueNamed(audit(Policy.WINDOWS_DOT_ENCODING_FILTER, "readme.txt"),
                FindingKind.FILTER_BYPASS);

        assertThat(bypass.detail()).contains("..%5c..%5c", "win.ini",
                "Rejected literal path: " + "..\\".repeat(16) + "windows\\win.ini");
    }

    @Test
    void staysSilentOnAContainedWindowsReader() {
        assertThat(audit(Policy.WINDOWS_CONTAINED, "readme.txt")).isEmpty();
    }

    @Test
    void reportsAWindowsFileUriReaderAsAnArbitraryHostFileRead() {
        assertThat(issueNamed(audit(Policy.WINDOWS_FILE_URI_READER, "file:///c:/srv/workspace/readme.txt"),
                FindingKind.HOST_FILE_READ).detail()).contains("file:///c:/windows/win.ini");
    }

    @Test
    void readsWinIniFromAWindowsNtSystemDirectory() {
        assertThat(issueNamed(audit(Policy.WINNT_TRAVERSAL_READER, "readme.txt"), FindingKind.FILE_READ).detail())
                .contains("winnt\\win.ini", "m" + "cpscan-0011223344-winnt");
    }

    @Test
    void reportsAnUncommonGitSpellingPastACaseSensitiveDenylist() {
        AuditIssue bypass = issueNamed(audit(Policy.CASE_SENSITIVE_GIT_DENYLIST, "notes.md"),
                FindingKind.RESTRICTED_PATH_BYPASS);

        assertThat(bypass.detail()).contains("The field rejected .git/config but returned",
                "Rejected literal path: .git/config");
    }

    @Test
    void readsAHostFileFromTheOneDepthAResolverAboveTheRootStillAccepts() {
        AuditIssue read = issueNamed(audit(Policy.RAW_PREFIX_CHECK_STRICT_RESOLVER, ROOT_FILE),
                FindingKind.FILE_READ);

        assertThat(read.detail()).contains(SimulatedFileTool.ROOT + "/../../etc/passwd");
    }

    @Test
    void staysSilentOnAContainedReaderGivenAnAbsoluteBaseValue() {
        assertThat(audit(Policy.CONTAINED, ROOT_FILE)).isEmpty();
    }

    @Test
    void ignoresNonMcpRequests() {
        Http http = mock(Http.class);
        HttpRequestResponse base = HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post(PathArgumentInsertionPoint.URL, Map.of(), "{\"path\":\"x\"}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{}"));

        assertThat(check.audit(base, new PathArgumentInsertionPoint("x"), http)).isEmpty();
        verifyNoInteractions(http);
        assertThat(skipLines()).singleElement().asString().startsWith("skipped field ")
                .endsWith(" (not applicable: not an MCP request)");
    }

    @Test
    void stopsProbingAFieldAtTheFirstHttp429() {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.CONTAINED).rateLimitingAfter(2);
        PathArgumentInsertionPoint point = new PathArgumentInsertionPoint("readme.txt");

        assertThat(check.audit(point.base(), point, tool.http())).isEmpty();

        assertThat(tool.sent()).hasSize(3);
        assertThat(skipLines()).singleElement().asString()
                .startsWith("stopped field " + point.name() + " of tools/call read_file at ")
                .endsWith(" (rate limited: the server answered HTTP 429)");
    }

    @Test
    void keepsADisclosureProvenBeforeAnHttp429() {
        PathArgumentInsertionPoint point = new PathArgumentInsertionPoint("readme.txt");
        SimulatedFileTool unlimited = new SimulatedFileTool(Policy.UNRESTRICTED);
        check.audit(point.base(), point, unlimited.http());
        SimulatedFileTool tool = new SimulatedFileTool(Policy.UNRESTRICTED)
                .rateLimitingAfter(unlimited.sent().size() - 1);

        List<AuditIssue> issues = check.audit(point.base(), point, tool.http());

        assertThat(issueNamed(issues, FindingKind.HOST_FILE_READ)).isNotNull();
        assertThat(skipLines()).singleElement().asString().endsWith(" (rate limited: the server answered HTTP 429)");
    }

    @Test
    void confirmsAndReportsAHitWhoseReplySaysTheRateLimitQuotaIsSpent() {
        List<AuditIssue> issues = audit(new SimulatedFileTool(Policy.UNRESTRICTED).spendingTheQuotaOnceAFileLeaks(),
                "readme.txt");

        assertThat(issueNamed(issues, FindingKind.HOST_FILE_READ).detail()).contains(MISSING);
    }

    @Test
    void stillProvesAFilterBypassWhenTheQuotaIsSpentByTheLeak() {
        assertThat(audit(new SimulatedFileTool(Policy.DECODE_AFTER_CHECK).spendingTheQuotaOnceAFileLeaks(),
                "readme.txt")).extracting(AuditIssue::name).contains(FindingKind.FILTER_BYPASS.issueName());
    }

    @Test
    void stopsProbingAFieldOnceAReplySaysTheRateLimitQuotaIsSpent() {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.CONTAINED).spendingTheQuotaFromTheFirstReply();

        assertThat(audit(tool, "readme.txt")).isEmpty();

        assertThat(tool.sent()).hasSize(1);
    }

    @ParameterizedTest
    @EnumSource(Policy.class)
    void boundsTheRequestsSentPerInsertionPoint(Policy policy) {
        SimulatedFileTool tool = new SimulatedFileTool(policy);
        PathArgumentInsertionPoint point = new PathArgumentInsertionPoint("docs/readme.txt");

        check.audit(point.base(), point, tool.http());

        assertThat(tool.sent()).hasSizeLessThanOrEqualTo(3 * TraversalPayloads.forBaseValue("docs/readme.txt").size() + 2);
    }

    @Test
    void keepsOneIssuePerNameAndFieldAndBothForDifferentNames() {
        AuditIssue first = issueNamed(audit(Policy.UNRESTRICTED, "readme.txt"), FindingKind.HOST_FILE_READ);
        AuditIssue repeat = issueNamed(audit(Policy.UNRESTRICTED, "other.txt"), FindingKind.HOST_FILE_READ);
        AuditIssue otherName = issueNamed(audit(Policy.CASE_INSENSITIVE_FILESYSTEM, "readme.txt"),
                FindingKind.REPOSITORY_METADATA_READ);

        assertThat(check.consolidate(first, repeat)).isEqualTo(ConsolidationAction.KEEP_EXISTING);
        assertThat(check.consolidate(first, otherName)).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    @Test
    void namesBurpsSameKeyedArgumentPointsByTheirFullPathsAndKeepsAnIssueForEach() {
        HttpRequestResponse base = HttpRequestResponse.httpRequestResponse(ImmutableHttpRequest.post(
                PathArgumentInsertionPoint.URL, Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"copy_file\","
                        + "\"arguments\":{\"source\":{\"path\":\"readme.txt\"},\"dest\":{\"path\":\"readme.txt\"}}}}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                        + "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}"));

        AuditIssue source = burpPointIssue(base, "source");
        AuditIssue dest = burpPointIssue(base, "dest");

        assertThat(source.detail()).contains("Field: MCP field: params.arguments.source.path.");
        assertThat(dest.detail()).contains("Field: MCP field: params.arguments.dest.path.");
        assertThat(besideBurpNativeFields.consolidate(source, dest)).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    private AuditIssue burpPointIssue(HttpRequestResponse base, String argument) {
        SimulatedFileTool tool = new SimulatedFileTool(Policy.UNRESTRICTED).reading(argument, "path");
        return issueNamed(besideBurpNativeFields.audit(base,
                new BurpArgumentPoint(base.request(), "arguments", argument, "path"), tool.http()),
                FindingKind.HOST_FILE_READ);
    }

    private List<AuditIssue> audit(Policy policy, String baseValue) {
        return audit(new SimulatedFileTool(policy), baseValue);
    }

    private List<AuditIssue> audit(SimulatedFileTool tool, String baseValue) {
        PathArgumentInsertionPoint point = new PathArgumentInsertionPoint(baseValue);
        return check.audit(point.base(), point, tool.http());
    }

    private List<String> skipLines() {
        String prefix = CheckLog.prefix(FileTraversalDescriptor.DESCRIPTOR.id());
        return eventLog.snapshot().stream()
                .filter(entry -> entry.level() == McpEventLog.Level.INFO)
                .map(McpEventLog.LogEntry::message)
                .filter(message -> message.startsWith(prefix))
                .map(message -> message.substring(prefix.length()))
                .toList();
    }

    private static AuditIssue issueNamed(List<AuditIssue> issues, FindingKind kind) {
        return issues.stream().filter(issue -> issue.name().equals(kind.issueName())).findFirst().orElseThrow(
                () -> new AssertionError(kind + " not in " + issues.stream().map(AuditIssue::name).toList()));
    }
}
