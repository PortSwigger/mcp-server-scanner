package com.mcpscanner.ui;

import com.mcpscanner.logging.McpEventLog;

import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

final class LogLine {

    static final int PREFIX_COLUMNS = 17;

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private LogLine() {
    }

    static String of(McpEventLog.LogEntry entry) {
        String time = LocalTime.ofInstant(entry.timestamp(), ZoneId.systemDefault()).format(TIME_FORMAT);
        return String.format("%s  %-5s  %s%n", time, entry.level().name(), entry.message());
    }

    static int lineCount(McpEventLog.LogEntry entry) {
        return (int) of(entry).chars().filter(character -> character == '\n').count();
    }
}
