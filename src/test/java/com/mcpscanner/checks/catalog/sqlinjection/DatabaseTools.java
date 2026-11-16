package com.mcpscanner.checks.catalog.sqlinjection;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.function.Function;

final class DatabaseTools {

    private final SqliteDatabase database;

    DatabaseTools(SqliteDatabase database) {
        this.database = database;
    }

    Function<String, ToolReply> splicedTableName() {
        return table -> run(() -> database.query("SELECT * FROM " + table + " LIMIT 100;"));
    }

    Function<String, ToolReply> splicedQuotedPragma() {
        return table -> run(() -> database.query("PRAGMA table_info('" + table + "')"));
    }

    Function<String, ToolReply> splicedQuotedTitle() {
        return title -> run(() -> database.query("SELECT body FROM notes WHERE title = \"" + title + "\""));
    }

    Function<String, ToolReply> splicedNumericId() {
        return id -> run(() -> database.query("SELECT title FROM notes WHERE id = " + id + " ORDER BY id"));
    }

    Function<String, ToolReply> splicedSingleQuotedTitle() {
        return title -> run(() -> {
            String bodies = database.query("SELECT body FROM notes WHERE title = '" + title + "'");
            return bodies.isEmpty() ? "no such note" : bodies;
        });
    }

    Function<String, ToolReply> explainedStatement() {
        return sql -> run(() -> {
            database.query("EXPLAIN " + sql);
            return "plan ready";
        });
    }

    Function<String, ToolReply> boundTitle() {
        return title -> run(() -> database.query("SELECT body FROM notes WHERE title = ?", title));
    }

    Function<String, ToolReply> validatedTableName() {
        return table -> table.matches("[A-Za-z_][A-Za-z0-9_]*")
                ? run(() -> database.query("SELECT * FROM \"" + table + "\""))
                : ToolReply.toolError("Invalid table name");
    }

    Function<String, ToolReply> rawStatement() {
        return sql -> run(() -> database.query(sql));
    }

    Function<String, ToolReply> sqlWordedValidator() {
        return value -> value.matches("[A-Za-z0-9 ]*") ? ToolReply.ok("Looked up " + value)
                : ToolReply.toolError("Invalid input: SQL syntax error near '" + value + "' is not allowed");
    }

    static Function<String, ToolReply> regexSearch() {
        List<String> lines = List.of("alpha line", "beta line");
        return pattern -> {
            try {
                Pattern compiled = Pattern.compile(pattern);
                List<String> matches = lines.stream().filter(line -> compiled.matcher(line).find()).toList();
                return ToolReply.ok(matches.isEmpty() ? "No matches" : String.join("\n", matches));
            } catch (PatternSyntaxException invalid) {
                return ToolReply.toolError("Invalid pattern: " + invalid.getDescription());
            }
        };
    }

    static Function<String, ToolReply> lenientlyDecodedName() {
        Map<String, String> people = Map.of("alice", "Alice Smith");
        return raw -> {
            String name = decodedJsonString(raw);
            return people.containsKey(name) ? ToolReply.ok("Name: " + people.get(name)) : ToolReply.ok("not found");
        };
    }

    static Function<String, ToolReply> flaky(long seed) {
        Random random = new Random(seed);
        return value -> random.nextBoolean() ? ToolReply.ok("ok") : ToolReply.toolError("upstream unavailable");
    }

    static Function<String, ToolReply> reflecting() {
        return value -> ToolReply.ok("Echo: " + value);
    }

    private static String decodedJsonString(String raw) {
        try {
            JsonNode node = McpObjectMapper.INSTANCE.readTree(raw);
            return node != null && node.isTextual() ? node.textValue() : raw;
        } catch (Exception notJson) {
            return raw;
        }
    }

    private static ToolReply run(Query query) {
        try {
            return ToolReply.ok(query.run());
        } catch (SQLException failure) {
            return ToolReply.toolError("Database error: " + failure.getMessage());
        }
    }

    @FunctionalInterface
    private interface Query {
        String run() throws SQLException;
    }
}
