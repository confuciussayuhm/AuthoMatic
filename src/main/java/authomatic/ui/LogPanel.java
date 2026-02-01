package authomatic.ui;

import authomatic.util.Logger;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;

/**
 * Panel displaying the activity log.
 */
public class LogPanel extends JPanel {

    private final JTextPane logArea;
    private final StyledDocument doc;
    private final Style infoStyle;
    private final Style warnStyle;
    private final Style errorStyle;
    private final Style debugStyle;
    private final Logger logger;

    public LogPanel(Logger logger) {
        this.logger = logger;
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Activity Log"));

        // Create styled text pane
        logArea = new JTextPane();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        doc = logArea.getStyledDocument();

        // Create styles for different log levels
        infoStyle = doc.addStyle("info", null);
        StyleConstants.setForeground(infoStyle, Color.BLACK);

        warnStyle = doc.addStyle("warn", null);
        StyleConstants.setForeground(warnStyle, new Color(180, 100, 0));

        errorStyle = doc.addStyle("error", null);
        StyleConstants.setForeground(errorStyle, Color.RED);

        debugStyle = doc.addStyle("debug", null);
        StyleConstants.setForeground(debugStyle, Color.GRAY);

        // Add scroll pane
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(600, 150));
        add(scrollPane, BorderLayout.CENTER);

        // Add clear button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton clearButton = new JButton("Clear Log");
        clearButton.addActionListener(e -> clearLog());
        buttonPanel.add(clearButton);
        add(buttonPanel, BorderLayout.SOUTH);

        // Load existing log entries
        for (Logger.LogEntry entry : logger.getLogEntries()) {
            appendEntry(entry);
        }

        // Listen for new entries
        logger.addListener(this::appendEntry);
    }

    private void appendEntry(Logger.LogEntry entry) {
        SwingUtilities.invokeLater(() -> {
            try {
                Style style;
                switch (entry.getLevel()) {
                    case WARN:
                        style = warnStyle;
                        break;
                    case ERROR:
                        style = errorStyle;
                        break;
                    case DEBUG:
                        style = debugStyle;
                        break;
                    default:
                        style = infoStyle;
                }

                doc.insertString(doc.getLength(), entry.toString() + "\n", style);

                // Auto-scroll to bottom
                logArea.setCaretPosition(doc.getLength());

                // Limit log size in UI
                if (doc.getLength() > 100000) {
                    doc.remove(0, 10000);
                }
            } catch (BadLocationException e) {
                // Ignore
            }
        });
    }

    private void clearLog() {
        try {
            doc.remove(0, doc.getLength());
            logger.clear();
        } catch (BadLocationException e) {
            // Ignore
        }
    }
}
