package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.function.Function;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;

class SqlInjectionCheckTest {

    private final SqliteDatabase database = new SqliteDatabase();
    private final DatabaseTools tools = new DatabaseTools(database);
    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @AfterEach
    void closeDatabase() throws Exception {
        database.close();
    }

    @Test
    void reportsATableNameSplicedIntoAStatementFirmlyWhenTwoSyntaxFamiliesAgree() {
        List<AuditIssue> issues = audit(tool("get_all_items", "table_name", "notes", tools.splicedTableName()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP SQL injection");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("get_all_items").contains("params.arguments.table_name")
                    .contains("SQL line comment");
            assertThat(issue.requestResponses()).hasSize(14);
        });
    }

    @Test
    void reportsAMissingTableSplicedIntoAStatement() {
        assertThat(audit(tool("get_all_items", "table_name", "test", tools.splicedTableName()))).hasSize(1);
    }

    @Test
    void reportsATableNameSplicedIntoAQuotedPragmaArgument() {
        assertThat(audit(tool("describe_table", "table_name", "notes", tools.splicedQuotedPragma())))
                .singleElement().satisfies(issue -> assertThat(issue.detail())
                        .contains("closing single quote and parenthesis"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"first", "test"})
    void reportsAValueSplicedIntoASingleQuotedLiteralWhetherOrNotItMatchesARow(String baseValue) {
        assertThat(audit(tool("find_note", "title", baseValue, tools.splicedSingleQuotedTitle())))
                .singleElement().satisfies(issue -> assertThat(issue.detail()).contains("closing single quote"));
    }

    @Test
    void reportsAValueSplicedIntoADoubleQuotedLiteral() {
        assertThat(audit(tool("find_note", "title", "first", tools.splicedQuotedTitle())))
                .singleElement().satisfies(issue -> assertThat(issue.detail()).contains("closing double quote"));
    }

    @Test
    void reportsANumberSplicedIntoAStatement() {
        assertThat(audit(tool("get_note", "id", "1", tools.splicedNumericId()))).hasSize(1);
    }

    @Test
    void reportsATableNameSplicedFromTheHostOfAResourceUri() {
        assertThat(audit(SimulatedDatabaseServer.tableResource("notes", tools.validatedTableName()))).isEmpty();
        assertThat(audit(SimulatedDatabaseServer.tableResource("notes", tools.splicedTableName())))
                .singleElement().satisfies(issue -> assertThat(issue.detail())
                        .contains("URI segment &#39;notes&#39;").contains("backtick"));
    }

    @Test
    void staysSilentForABoundParameter() {
        assertThat(audit(tool("find_note", "title", "first", tools.boundTitle()))).isEmpty();
    }

    @Test
    void staysSilentForAValidatedIdentifier() {
        assertThat(audit(tool("get_all_items", "table_name", "notes", tools.validatedTableName()))).isEmpty();
    }

    @Test
    void staysSilentForAFieldThatRunsWholeStatementsByDesign() {
        assertThat(audit(tool("execute_query", "query", "SELECT title FROM notes", tools.rawStatement()))).isEmpty();
        assertThat(skipLines()).anyMatch(line -> line.contains("runs whole SQL statements by design"));
    }

    @Test
    void staysSilentForAFieldThatRunsStatementsWithoutReturningTheirResult() {
        assertThat(audit(tool("explain_query", "sql", "SELECT title FROM notes", tools.explainedStatement())))
                .isEmpty();
        assertThat(skipLines()).anyMatch(line -> line.contains("runs whole SQL statements by design"));
    }

    @Test
    void staysSilentForAFieldThatOnlyReflectsItsInput() {
        SimulatedDatabaseServer server = tool("echo", "message", "notes", DatabaseTools.reflecting());

        assertThat(audit(server)).isEmpty();
        assertThat(server.receivedValues()).hasSizeLessThanOrEqualTo(2 * EquivalenceProbe.INSENSITIVE_FORMS_BEFORE_GIVING_UP);
    }

    @Test
    void staysSilentForAValidatorWhoseErrorMentionsSqlSyntax() {
        assertThat(audit(tool("lookup", "name", "notes", tools.sqlWordedValidator()))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"test", "alpha"})
    void staysSilentForARegularExpressionField(String baseValue) {
        assertThat(audit(tool("search_code", "pattern", baseValue, DatabaseTools.regexSearch()))).isEmpty();
    }

    @Test
    void staysSilentForAnArgumentDecodedAsJsonWhenItParses() {
        assertThat(audit(tool("get_person", "name", "alice", DatabaseTools.lenientlyDecodedName()))).isEmpty();
    }

    @Test
    void staysSilentForAToolWhoseReplyFlipsAtRandom() {
        long reports = LongStream.range(0, 200)
                .filter(seed -> !audit(tool("status", "table", "notes", DatabaseTools.flaky(seed))).isEmpty())
                .count();

        assertThat(reports).isZero();
    }

    @Test
    void staysSilentWhenTheBaselineIsNotReproducible() {
        int[] calls = {0};
        Function<String, ToolReply> volatileSplice = table -> ToolReply.ok(
                tools.splicedTableName().apply(table).text() + " request " + calls[0]++);

        assertThat(audit(tool("get_all_items", "table_name", "notes", volatileSplice))).isEmpty();
    }

    private SimulatedDatabaseServer tool(String name, String argument, String baseValue,
                                         Function<String, ToolReply> behaviour) {
        return SimulatedDatabaseServer.tool(name, argument, baseValue, behaviour);
    }

    private List<AuditIssue> audit(SimulatedDatabaseServer server) {
        HttpRequestResponse base = server.baseline();
        return new SqlInjectionCheck(BurpNativeJsonRpcFields.ABSENT, eventLog)
                .audit(base, server.field(base), server.http());
    }

    private List<String> skipLines() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
