package authomatic.ui;

import authomatic.auth.AuthManager;
import authomatic.config.AuthConfig;
import authomatic.config.ConfigManager;
import authomatic.config.HostConfig;
import authomatic.service.ManualInjectionService;
import authomatic.util.Logger;

import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;

/**
 * Main UI panel for AuthoMatic extension.
 */
public class AuthoMaticTab extends JPanel {

    private final AuthConfig config;
    private final ConfigManager configManager;
    private final AuthManager authManager;
    private final Logger logger;

    private final JCheckBox globalEnabledCheckbox;
    private final JTextField rateLimitField;
    private final JTable hostTable;
    private final HostTableModel hostTableModel;
    private final HostConfigPanel hostConfigPanel;
    private InjectionHistoryPanel injectionHistoryPanel;
    private boolean isSelecting = false;

    public AuthoMaticTab(AuthConfig config, ConfigManager configManager, AuthManager authManager, Logger logger) {
        this.config = config;
        this.configManager = configManager;
        this.authManager = authManager;
        this.logger = logger;

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top panel - Global settings
        JPanel globalPanel = createGlobalSettingsPanel();
        add(globalPanel, BorderLayout.NORTH);

        // Center panel - Split between host list and config
        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        centerSplit.setResizeWeight(0.4);

        // Host table
        hostTableModel = new HostTableModel();
        hostTable = new JTable(hostTableModel);
        hostTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        hostTable.getColumnModel().getColumn(0).setMaxWidth(60);
        hostTable.getColumnModel().getColumn(0).setMinWidth(60);
        hostTable.getSelectionModel().addListSelectionListener(this::onHostSelected);

        JPanel hostTablePanel = new JPanel(new BorderLayout());
        hostTablePanel.setBorder(BorderFactory.createTitledBorder("Host Configurations"));
        hostTablePanel.add(new JScrollPane(hostTable), BorderLayout.CENTER);
        hostTablePanel.add(createHostButtonPanel(), BorderLayout.SOUTH);
        centerSplit.setTopComponent(hostTablePanel);

        // Host config panel
        hostConfigPanel = new HostConfigPanel(authManager);
        hostConfigPanel.setOnChangeListener(this::onConfigChanged);
        hostConfigPanel.setOnImportListener(this::onImportConfig);
        centerSplit.setBottomComponent(hostConfigPanel);

        add(centerSplit, BorderLayout.CENTER);

        // Initialize UI state
        globalEnabledCheckbox = (JCheckBox) ((JPanel) globalPanel.getComponent(0)).getComponent(0);
        rateLimitField = (JTextField) ((JPanel) globalPanel.getComponent(0)).getComponent(2);
        loadConfigToUI();
    }

    /**
     * Sets up the injection history panel. Called after ManualInjectionService is created.
     */
    public void setInjectionService(ManualInjectionService injectionService) {
        if (injectionHistoryPanel != null) {
            return; // Already set
        }

        injectionHistoryPanel = new InjectionHistoryPanel(injectionService);

        // Create tabbed pane at the bottom with configuration and injection history
        JTabbedPane bottomTabs = new JTabbedPane();
        bottomTabs.addTab("Host Configuration", hostConfigPanel);
        bottomTabs.addTab("Injection History", injectionHistoryPanel);

        // Update the center split pane to use the tabbed pane
        Component centerComponent = getComponent(1); // CENTER is the second component after NORTH
        if (centerComponent instanceof JSplitPane) {
            JSplitPane centerSplit = (JSplitPane) centerComponent;
            centerSplit.setBottomComponent(bottomTabs);
        }
    }

    private JPanel createGlobalSettingsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Global Settings"));

        JPanel innerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JCheckBox enabledCheckbox = new JCheckBox("Enable AuthoMatic");
        enabledCheckbox.setSelected(config.isGlobalEnabled());
        enabledCheckbox.addActionListener(e -> {
            config.setGlobalEnabled(enabledCheckbox.isSelected());
            saveConfig();
        });
        innerPanel.add(enabledCheckbox);

        innerPanel.add(new JLabel("Rate Limit (ms):"));

        JTextField rateLimitTextField = new JTextField(6);
        rateLimitTextField.setText(String.valueOf(config.getRateLimitIntervalMs()));
        rateLimitTextField.addActionListener(e -> {
            try {
                long value = Long.parseLong(rateLimitTextField.getText().trim());
                config.setRateLimitIntervalMs(value);
                authManager.getRateLimiter().setIntervalMs(value);
                saveConfig();
            } catch (NumberFormatException ex) {
                rateLimitTextField.setText(String.valueOf(config.getRateLimitIntervalMs()));
            }
        });
        innerPanel.add(rateLimitTextField);

        JButton clearCacheButton = new JButton("Clear Token Cache");
        clearCacheButton.addActionListener(e -> {
            authManager.clearAllCache();
            JOptionPane.showMessageDialog(this, "Token cache cleared", "AuthoMatic", JOptionPane.INFORMATION_MESSAGE);
        });
        innerPanel.add(clearCacheButton);

        panel.add(innerPanel, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createHostButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> addHost());
        panel.add(addButton);

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> removeHost());
        panel.add(removeButton);

        JButton duplicateButton = new JButton("Duplicate");
        duplicateButton.addActionListener(e -> duplicateHost());
        panel.add(duplicateButton);

        return panel;
    }

    private void loadConfigToUI() {
        hostTableModel.fireTableDataChanged();
        if (!config.getHostConfigs().isEmpty()) {
            hostTable.setRowSelectionInterval(0, 0);
        }
    }

    private void onHostSelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting() || isSelecting) return;

        isSelecting = true;
        try {
            int row = hostTable.getSelectedRow();
            if (row >= 0 && row < config.getHostConfigs().size()) {
                hostConfigPanel.saveToConfig();  // Save previous selection
                hostConfigPanel.setConfig(config.getHostConfigs().get(row));
            } else {
                hostConfigPanel.setConfig(null);
            }
        } finally {
            isSelecting = false;
        }
    }

    private void onConfigChanged() {
        if (!isSelecting) {
            int selectedRow = hostTable.getSelectedRow();
            hostTableModel.fireTableDataChanged();
            // Restore selection after table refresh
            if (selectedRow >= 0 && selectedRow < config.getHostConfigs().size()) {
                hostTable.setRowSelectionInterval(selectedRow, selectedRow);
            }
        }
        saveConfig();
    }

    private void addHost() {
        HostConfig newConfig = new HostConfig();
        newConfig.setUrlPattern("example.com/**");
        newConfig.setLoginUrl("https://example.com/api/auth/login");
        newConfig.setLoginBody("{\"username\": \"${username}\", \"password\": \"${password}\"}");
        config.addHostConfig(newConfig);
        hostTableModel.fireTableDataChanged();
        hostTable.setRowSelectionInterval(config.getHostConfigs().size() - 1, config.getHostConfigs().size() - 1);
        saveConfig();
    }

    private void removeHost() {
        int[] selectedRows = hostTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        String message;
        if (selectedRows.length == 1) {
            message = "Remove configuration for " + config.getHostConfigs().get(selectedRows[0]).getUrlPattern() + "?";
        } else {
            message = "Remove " + selectedRows.length + " selected configurations?";
        }

        int confirm = JOptionPane.showConfirmDialog(this, message, "Confirm Remove", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            // Remove in reverse order to preserve indices
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                int row = selectedRows[i];
                if (row >= 0 && row < config.getHostConfigs().size()) {
                    config.getHostConfigs().remove(row);
                }
            }
            hostTableModel.fireTableDataChanged();
            hostConfigPanel.setConfig(null);
            saveConfig();
        }
    }

    private void duplicateHost() {
        int row = hostTable.getSelectedRow();
        if (row >= 0 && row < config.getHostConfigs().size()) {
            HostConfig original = config.getHostConfigs().get(row);
            HostConfig copy = original.copy();
            copy.setUrlPattern(original.getUrlPattern() + "-copy");
            config.addHostConfig(copy);
            hostTableModel.fireTableDataChanged();
            hostTable.setRowSelectionInterval(config.getHostConfigs().size() - 1, config.getHostConfigs().size() - 1);
            saveConfig();
        }
    }

    private void saveConfig() {
        hostConfigPanel.saveToConfig();
        configManager.save();
    }

    private void onImportConfig(HostConfig importedConfig) {
        // Add the imported config
        config.addHostConfig(importedConfig);
        hostTableModel.fireTableDataChanged();

        // Select the new config
        int newIndex = config.getHostConfigs().size() - 1;
        hostTable.setRowSelectionInterval(newIndex, newIndex);
        hostConfigPanel.setConfig(importedConfig);

        saveConfig();
        logger.info("Imported configuration for: " + importedConfig.getUrlPattern());
    }

    /**
     * Opens the ImportDialog pre-populated with the given request/response.
     * Called from context menu when user right-clicks on a request/response pair.
     */
    public void openImportDialogWithData(HttpRequestResponse requestResponse) {
        SwingUtilities.invokeLater(() -> {
            Window owner = SwingUtilities.getWindowAncestor(this);
            ImportDialog dialog = new ImportDialog(owner);

            // Convert Burp HttpRequest/HttpResponse to raw text
            String requestText = requestResponse.request().toByteArray().toString();
            String responseText = requestResponse.response() != null
                    ? requestResponse.response().toByteArray().toString()
                    : "";

            dialog.setRequestResponse(requestText, responseText);
            dialog.setVisible(true);

            if (dialog.isImported()) {
                onImportConfig(dialog.getResultConfig());
            }
        });
    }

    /**
     * Table model for host configurations.
     */
    private class HostTableModel extends AbstractTableModel {
        private final String[] columns = {"Enabled", "URL Pattern", "Login URL"};

        @Override
        public int getRowCount() {
            return config.getHostConfigs().size();
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
        public Class<?> getColumnClass(int column) {
            if (column == 0) return Boolean.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;  // Only enabled checkbox is editable directly
        }

        @Override
        public Object getValueAt(int row, int column) {
            if (row >= config.getHostConfigs().size()) return null;
            HostConfig host = config.getHostConfigs().get(row);
            switch (column) {
                case 0:
                    return host.isEnabled();
                case 1:
                    return host.getUrlPattern();
                case 2:
                    return host.getLoginUrl();
                default:
                    return null;
            }
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column == 0 && row < config.getHostConfigs().size()) {
                config.getHostConfigs().get(row).setEnabled((Boolean) value);
                saveConfig();
            }
        }
    }
}
