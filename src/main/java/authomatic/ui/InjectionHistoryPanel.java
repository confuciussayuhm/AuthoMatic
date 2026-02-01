package authomatic.ui;

import authomatic.model.InjectionRecord;
import authomatic.service.ManualInjectionService;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel showing injection history with before/after diff view.
 */
public class InjectionHistoryPanel extends JPanel implements ManualInjectionService.InjectionListener {

    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final ManualInjectionService injectionService;
    private final JTable historyTable;
    private final HistoryTableModel tableModel;
    private final JTextArea beforeArea;
    private final JTextArea afterArea;
    private final List<InjectionRecord> records = new ArrayList<>();

    public InjectionHistoryPanel(ManualInjectionService injectionService) {
        this.injectionService = injectionService;
        injectionService.addListener(this);

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createTitledBorder("Injection History"));

        // Create split pane: table on top, diff view below
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.4);

        // History table
        tableModel = new HistoryTableModel();
        historyTable = new JTable(tableModel);
        historyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRowSelected();
            }
        });

        // Set column widths
        historyTable.getColumnModel().getColumn(0).setPreferredWidth(70);
        historyTable.getColumnModel().getColumn(0).setMaxWidth(100);
        historyTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        historyTable.getColumnModel().getColumn(3).setPreferredWidth(200);

        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.add(new JScrollPane(historyTable), BorderLayout.CENTER);
        tablePanel.add(createButtonPanel(), BorderLayout.SOUTH);
        splitPane.setTopComponent(tablePanel);

        // Diff view - side by side
        JPanel diffPanel = new JPanel(new GridLayout(1, 2, 5, 0));
        diffPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));

        // Before panel
        JPanel beforePanel = new JPanel(new BorderLayout());
        beforePanel.setBorder(BorderFactory.createTitledBorder("Before"));
        beforeArea = new JTextArea();
        beforeArea.setEditable(false);
        beforeArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        beforeArea.setLineWrap(false);
        beforePanel.add(new JScrollPane(beforeArea), BorderLayout.CENTER);
        diffPanel.add(beforePanel);

        // After panel
        JPanel afterPanel = new JPanel(new BorderLayout());
        afterPanel.setBorder(BorderFactory.createTitledBorder("After"));
        afterArea = new JTextArea();
        afterArea.setEditable(false);
        afterArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        afterArea.setLineWrap(false);
        afterPanel.add(new JScrollPane(afterArea), BorderLayout.CENTER);
        diffPanel.add(afterPanel);

        splitPane.setBottomComponent(diffPanel);

        add(splitPane, BorderLayout.CENTER);

        // Load existing history
        refreshFromService();
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton clearButton = new JButton("Clear History");
        clearButton.addActionListener(e -> {
            injectionService.clearHistory();
            records.clear();
            tableModel.fireTableDataChanged();
            clearDiffView();
        });
        panel.add(clearButton);

        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refreshFromService());
        panel.add(refreshButton);

        return panel;
    }

    private void refreshFromService() {
        records.clear();
        records.addAll(injectionService.getInjectionHistory());
        tableModel.fireTableDataChanged();
        if (!records.isEmpty()) {
            historyTable.setRowSelectionInterval(0, 0);
        } else {
            clearDiffView();
        }
    }

    private void onRowSelected() {
        int row = historyTable.getSelectedRow();
        if (row >= 0 && row < records.size()) {
            InjectionRecord record = records.get(row);
            beforeArea.setText(record.getFullRequestBefore());
            afterArea.setText(record.getFullRequestAfter());

            // Scroll to show the changed area
            try {
                int caretPos = Math.min(record.getSelectionStart(), beforeArea.getText().length());
                beforeArea.setCaretPosition(caretPos);
                afterArea.setCaretPosition(caretPos);
            } catch (Exception ignored) {
            }
        } else {
            clearDiffView();
        }
    }

    private void clearDiffView() {
        beforeArea.setText("");
        afterArea.setText("");
    }

    @Override
    public void onInjectionPerformed(InjectionRecord record) {
        SwingUtilities.invokeLater(() -> {
            records.add(0, record);
            tableModel.fireTableDataChanged();
            if (records.size() == 1) {
                historyTable.setRowSelectionInterval(0, 0);
            }
        });
    }

    /**
     * Table model for injection history.
     */
    private class HistoryTableModel extends AbstractTableModel {
        private final String[] columns = {"Time", "URL", "Host Pattern", "Token Preview"};

        @Override
        public int getRowCount() {
            return records.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            if (row >= records.size()) return null;
            InjectionRecord record = records.get(row);
            switch (column) {
                case 0:
                    return record.getTimestamp().format(TIME_FORMATTER);
                case 1:
                    return truncateUrl(record.getRequestUrl());
                case 2:
                    return record.getHostConfigPattern();
                case 3:
                    return record.getTokenPreview();
                default:
                    return null;
            }
        }

        private String truncateUrl(String url) {
            if (url == null) return "";
            if (url.length() <= 50) return url;
            return url.substring(0, 47) + "...";
        }
    }
}
