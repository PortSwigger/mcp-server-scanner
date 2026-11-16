package com.mcpscanner.checks.catalog.sqlinjection;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

final class SqliteDatabase implements AutoCloseable {

    private final Connection connection;

    SqliteDatabase() {
        try {
            connection = DriverManager.getConnection("jdbc:sqlite::memory:");
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)");
                statement.executeUpdate("INSERT INTO notes (title, body) VALUES ('first', 'alpha'), ('second', 'beta')");
                statement.executeUpdate("CREATE TABLE secrets (token TEXT)");
                statement.executeUpdate("INSERT INTO secrets VALUES ('s3cr3t')");
            }
        } catch (SQLException failure) {
            throw new IllegalStateException(failure);
        }
    }

    String query(String sql) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            return rendered(rows);
        }
    }

    String query(String sql, String parameter) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, parameter);
            try (ResultSet rows = statement.executeQuery()) {
                return rendered(rows);
            }
        }
    }

    private static String rendered(ResultSet rows) throws SQLException {
        ResultSetMetaData columns = rows.getMetaData();
        List<String> lines = new ArrayList<>();
        while (rows.next()) {
            List<String> cells = new ArrayList<>();
            for (int column = 1; column <= columns.getColumnCount(); column++) {
                cells.add(columns.getColumnName(column) + "=" + rows.getString(column));
            }
            lines.add(String.join(",", cells));
        }
        return String.join("\n", lines);
    }

    @Override
    public void close() throws SQLException {
        connection.close();
    }
}
