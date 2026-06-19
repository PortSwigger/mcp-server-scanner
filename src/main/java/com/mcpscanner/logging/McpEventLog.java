package com.mcpscanner.logging;

import burp.api.montoya.logging.Logging;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class McpEventLog {

    public enum Level { INFO, WARN, ERROR }

    private static final int MAX_LINES = 1000;
    private static final McpEventLog NOOP = new NoopEventLog();

    /** Returns a singleton no-op instance whose write methods silently discard all messages. */
    public static McpEventLog noop() {
        return NOOP;
    }

    private final Deque<LogEntry> entries = new ArrayDeque<>(MAX_LINES);
    private final List<Consumer<LogEntry>> listeners = new CopyOnWriteArrayList<>();
    private final Logging burpLogging;
    private final ExecutorService fanoutExecutor;

    public McpEventLog(Logging burpLogging) {
        this(burpLogging, defaultFanoutExecutor());
    }

    McpEventLog(Logging burpLogging, ExecutorService fanoutExecutor) {
        this.burpLogging = burpLogging;
        this.fanoutExecutor = fanoutExecutor;
    }

    private McpEventLog() {
        this.burpLogging = null;
        this.fanoutExecutor = null;
    }

    private static ExecutorService defaultFanoutExecutor() {
        return new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                r -> {
                    Thread t = new Thread(r, "McpEventLog-fanout");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.DiscardPolicy());
    }

    public void info(String message) {
        append(Level.INFO, message, null);
    }

    public void warn(String message) {
        append(Level.WARN, message, null);
    }

    public void error(String message) {
        append(Level.ERROR, message, null);
    }

    public void error(String message, Throwable t) {
        append(Level.ERROR, message, t);
    }

    void addListener(Consumer<LogEntry> listener) {
        listeners.add(listener);
    }

    public List<LogEntry> subscribe(Consumer<LogEntry> listener) {
        synchronized (entries) {
            listeners.add(listener);
            return List.copyOf(entries);
        }
    }

    public List<LogEntry> snapshot() {
        synchronized (entries) {
            return List.copyOf(entries);
        }
    }

    public void shutdown() {
        fanoutExecutor.shutdownNow();
        listeners.clear();
    }

    private void append(Level level, String message, Throwable throwable) {
        LogEntry entry = new LogEntry(Instant.now(), level, message, throwable);
        synchronized (entries) {
            if (entries.size() == MAX_LINES) {
                entries.removeFirst();
            }
            entries.addLast(entry);
            List<Consumer<LogEntry>> recipients = List.copyOf(listeners);
            fanoutExecutor.execute(() -> notifyListeners(recipients, entry));
        }
        mirrorToBurp(entry);
    }

    private void notifyListeners(List<Consumer<LogEntry>> recipients, LogEntry entry) {
        for (Consumer<LogEntry> listener : recipients) {
            deliverGuarded(listener, entry);
        }
    }

    private void deliverGuarded(Consumer<LogEntry> listener, LogEntry entry) {
        try {
            listener.accept(entry);
        } catch (RuntimeException e) {
            if (burpLogging != null) {
                burpLogging.logToError("McpEventLog listener threw for " + entry.level() + " entry", e);
            }
        }
    }

    private void mirrorToBurp(LogEntry entry) {
        if (entry.level() != Level.ERROR || burpLogging == null) {
            return;
        }
        if (entry.throwable() != null) {
            burpLogging.logToError(entry.message(), entry.throwable());
        } else {
            burpLogging.logToError(entry.message());
        }
    }

    public record LogEntry(Instant timestamp, Level level, String message, Throwable throwable) {}

    private static final class NoopEventLog extends McpEventLog {
        private NoopEventLog() {}

        @Override public void info(String message) {}
        @Override public void warn(String message) {}
        @Override public void error(String message) {}
        @Override public void error(String message, Throwable t) {}
        @Override public void shutdown() {}
    }
}
