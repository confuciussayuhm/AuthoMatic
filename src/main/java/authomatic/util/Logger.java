package authomatic.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Centralized logging for AuthoMatic extension.
 * Logs to Burp's output and maintains an in-memory log for the UI.
 */
public class Logger {

    private static final int MAX_LOG_ENTRIES = 1000;
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final Logging logging;
    private final List<LogEntry> logEntries = new CopyOnWriteArrayList<>();
    private final List<Consumer<LogEntry>> listeners = new CopyOnWriteArrayList<>();

    public Logger(MontoyaApi api) {
        this.logging = api.logging();
    }

    public void info(String message) {
        log(LogLevel.INFO, message);
    }

    public void warn(String message) {
        log(LogLevel.WARN, message);
    }

    public void error(String message) {
        log(LogLevel.ERROR, message);
    }

    public void debug(String message) {
        log(LogLevel.DEBUG, message);
    }

    private void log(LogLevel level, String message) {
        LogEntry entry = new LogEntry(LocalDateTime.now(), level, message);

        // Add to in-memory log
        logEntries.add(entry);
        while (logEntries.size() > MAX_LOG_ENTRIES) {
            logEntries.remove(0);
        }

        // Log to Burp output
        String formattedMessage = entry.toString();
        if (level == LogLevel.ERROR) {
            logging.logToError(formattedMessage);
        } else {
            logging.logToOutput(formattedMessage);
        }

        // Notify listeners
        for (Consumer<LogEntry> listener : listeners) {
            try {
                listener.accept(entry);
            } catch (Exception ignored) {
            }
        }
    }

    public List<LogEntry> getLogEntries() {
        return new ArrayList<>(logEntries);
    }

    public void addListener(Consumer<LogEntry> listener) {
        listeners.add(listener);
    }

    public void removeListener(Consumer<LogEntry> listener) {
        listeners.remove(listener);
    }

    public void clear() {
        logEntries.clear();
    }

    public enum LogLevel {
        DEBUG, INFO, WARN, ERROR
    }

    public static class LogEntry {
        private final LocalDateTime timestamp;
        private final LogLevel level;
        private final String message;

        public LogEntry(LocalDateTime timestamp, LogLevel level, String message) {
            this.timestamp = timestamp;
            this.level = level;
            this.message = message;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }

        public LogLevel getLevel() {
            return level;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return String.format("[%s] [%s] %s",
                    timestamp.format(TIME_FORMAT),
                    level.name(),
                    message);
        }
    }
}
