package authomatic.ui;

import authomatic.auth.AuthManager;
import authomatic.config.HostConfig;
import authomatic.config.TokenExtractionConfig;
import authomatic.config.TokenInjectionConfig;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.basic.BasicComboBoxRenderer;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * Panel for editing a single host configuration with side-by-side request/response view.
 */
public class HostConfigPanel extends JPanel {

    private final JTextField urlPatternField;
    private final JTextArea requestArea;
    private final TokenSelectionPanel tokenSelectionPanel;

    // Token selection controls (dropdown in bottom section)
    private final JComboBox<ParsedValueItem> tokenDropdown;
    private final JButton reparseButton;
    private final JLabel selectionPreviewLabel;
    private final JButton applySelectionButton;

    // Token injection controls
    private final JCheckBox injectionAutoDetect;
    private final JComboBox<InjectionOption> injectionTypeDropdown;
    private final JLabel injectionNameLabel;
    private final JTextField injectionNameField;
    private final JLabel injectionPreviewLabel;

    private HostConfig currentConfig;
    private final AuthManager authManager;
    private Runnable onChangeListener;
    private Consumer<HostConfig> onImportListener;

    public HostConfigPanel(AuthManager authManager) {
        this.authManager = authManager;
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Selected Host Configuration"));

        // Top panel with buttons and URL pattern
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Button row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JButton importButton = new JButton("Import from Request/Response...");
        importButton.setToolTipText("Import configuration from a raw HTTP login request and response");
        importButton.addActionListener(e -> openImportDialog());
        buttonRow.add(importButton);

        JPanel rightButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> saveToConfig());
        rightButtons.add(saveButton);
        JButton testButton = new JButton("Test Login");
        testButton.addActionListener(e -> testLogin());
        rightButtons.add(testButton);

        JPanel buttonPanel = new JPanel(new BorderLayout());
        buttonPanel.add(buttonRow, BorderLayout.WEST);
        buttonPanel.add(rightButtons, BorderLayout.EAST);
        topPanel.add(buttonPanel, BorderLayout.NORTH);

        // URL Pattern row
        JPanel patternRow = new JPanel(new BorderLayout(5, 0));
        patternRow.add(new JLabel("URL Pattern:"), BorderLayout.WEST);
        urlPatternField = new JTextField();
        urlPatternField.setToolTipText("e.g., api.example.com/api/* or *.example.com/**");
        patternRow.add(urlPatternField, BorderLayout.CENTER);
        topPanel.add(patternRow, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);

        // Center: Split pane with request/response
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);

        // Left: Request area
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Auth Request (editable)"));
        requestArea = new JTextArea();
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        requestArea.setLineWrap(false);
        requestArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                markDirty();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                markDirty();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                markDirty();
            }
        });
        JScrollPane requestScroll = new JScrollPane(requestArea);
        requestPanel.add(requestScroll, BorderLayout.CENTER);
        splitPane.setLeftComponent(requestPanel);

        // Right: Raw response panel (read-only)
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Auth Response (read-only)"));
        tokenSelectionPanel = new TokenSelectionPanel();
        responsePanel.add(tokenSelectionPanel, BorderLayout.CENTER);
        splitPane.setRightComponent(responsePanel);

        add(splitPane, BorderLayout.CENTER);

        // Bottom panel: Token Selection and Injection
        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Token Selection section with dropdown
        JPanel selectionPanel = new JPanel(new BorderLayout(5, 5));
        selectionPanel.setBorder(BorderFactory.createTitledBorder("Token Selection"));

        // Top row: dropdown + re-parse button
        JPanel dropdownRow = new JPanel(new BorderLayout(5, 0));

        tokenDropdown = new JComboBox<>();
        tokenDropdown.setRenderer(new CategoryAwareRenderer());
        tokenDropdown.addActionListener(e -> {
            if (e.getActionCommand().equals("comboBoxChanged")) {
                handleDropdownSelection();
            }
        });
        dropdownRow.add(tokenDropdown, BorderLayout.CENTER);

        JPanel dropdownButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        reparseButton = new JButton("Re-parse");
        reparseButton.setToolTipText("Re-parse the response to refresh token options");
        reparseButton.addActionListener(e -> parseResponse());
        dropdownButtons.add(reparseButton);

        applySelectionButton = new JButton("Apply Selection");
        applySelectionButton.setEnabled(false);
        applySelectionButton.addActionListener(e -> applySelection());
        dropdownButtons.add(applySelectionButton);

        dropdownRow.add(dropdownButtons, BorderLayout.EAST);
        selectionPanel.add(dropdownRow, BorderLayout.NORTH);

        // Bottom row: value preview
        JPanel previewRow = new JPanel(new BorderLayout(5, 0));
        previewRow.add(new JLabel("Value:"), BorderLayout.WEST);
        selectionPreviewLabel = new JLabel("(select a token from the dropdown)");
        selectionPreviewLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        previewRow.add(selectionPreviewLabel, BorderLayout.CENTER);
        selectionPanel.add(previewRow, BorderLayout.CENTER);

        bottomPanel.add(selectionPanel, BorderLayout.NORTH);

        // Token Injection section
        JPanel injectionPanel = new JPanel(new BorderLayout(5, 5));
        injectionPanel.setBorder(BorderFactory.createTitledBorder("Token Injection"));

        JPanel injectionControlsWrapper = new JPanel(new BorderLayout(5, 5));

        // Top row: auto-detect checkbox
        injectionAutoDetect = new JCheckBox("Auto-detect from token source", true);
        injectionAutoDetect.addActionListener(e -> updateInjectionFields());
        injectionControlsWrapper.add(injectionAutoDetect, BorderLayout.NORTH);

        // Middle row: dropdown and name field
        JPanel manualControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));

        manualControls.add(new JLabel("Inject as:"));
        injectionTypeDropdown = new JComboBox<>(new InjectionOption[] {
            new InjectionOption(TokenInjectionConfig.TargetType.AUTHORIZATION_BEARER,
                    "Authorization: Bearer {token}"),
            new InjectionOption(TokenInjectionConfig.TargetType.COOKIE,
                    "Cookie: {name}={token}"),
            new InjectionOption(TokenInjectionConfig.TargetType.HEADER,
                    "Header: {name}: {token}")
        });
        injectionTypeDropdown.addActionListener(e -> {
            updateInjectionNameFieldVisibility();
            updateInjectionPreview();
        });
        manualControls.add(injectionTypeDropdown);

        injectionNameLabel = new JLabel("Name:");
        manualControls.add(injectionNameLabel);

        injectionNameField = new JTextField(12);
        injectionNameField.setToolTipText("Cookie or header name");
        injectionNameField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { updateInjectionPreview(); }
            @Override
            public void removeUpdate(DocumentEvent e) { updateInjectionPreview(); }
            @Override
            public void changedUpdate(DocumentEvent e) { updateInjectionPreview(); }
        });
        manualControls.add(injectionNameField);

        injectionControlsWrapper.add(manualControls, BorderLayout.CENTER);

        // Bottom row: live preview
        JPanel previewPanel = new JPanel(new BorderLayout(5, 0));
        previewPanel.add(new JLabel("Will add to requests:"), BorderLayout.WEST);
        injectionPreviewLabel = new JLabel();
        injectionPreviewLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        injectionPreviewLabel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color.LIGHT_GRAY),
                BorderFactory.createEmptyBorder(2, 5, 2, 5)));
        injectionPreviewLabel.setOpaque(true);
        injectionPreviewLabel.setBackground(new Color(245, 245, 245));
        previewPanel.add(injectionPreviewLabel, BorderLayout.CENTER);

        injectionControlsWrapper.add(previewPanel, BorderLayout.SOUTH);

        injectionPanel.add(injectionControlsWrapper, BorderLayout.CENTER);
        bottomPanel.add(injectionPanel, BorderLayout.CENTER);

        add(bottomPanel, BorderLayout.SOUTH);

        // Initial state
        updateInjectionFields();
        setEnabled(false);
    }

    public void setOnChangeListener(Runnable listener) {
        this.onChangeListener = listener;
    }

    public void setOnImportListener(Consumer<HostConfig> listener) {
        this.onImportListener = listener;
    }

    private void openImportDialog() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        ImportDialog dialog = new ImportDialog(owner);
        dialog.setVisible(true);

        if (dialog.isImported()) {
            HostConfig importedConfig = dialog.getResultConfig();
            if (importedConfig != null && onImportListener != null) {
                onImportListener.accept(importedConfig);
            }
        }
    }

    /**
     * Parse the current response and populate the dropdown.
     */
    private void parseResponse() {
        tokenDropdown.removeAllItems();
        selectionPreviewLabel.setText("(select a token from the dropdown)");
        applySelectionButton.setEnabled(false);

        String rawResponse = tokenSelectionPanel.getText();
        if (rawResponse == null || rawResponse.isEmpty()) {
            return;
        }

        List<ParsedValueItem> items = ResponseParser.parse(rawResponse);

        if (items.isEmpty()) {
            tokenDropdown.addItem(ParsedValueItem.value(null, "(no tokens found)", ""));
            return;
        }

        for (ParsedValueItem item : items) {
            tokenDropdown.addItem(item);
        }

        // Select first non-category item
        for (int i = 0; i < tokenDropdown.getItemCount(); i++) {
            ParsedValueItem item = tokenDropdown.getItemAt(i);
            if (!item.isCategory()) {
                tokenDropdown.setSelectedIndex(i);
                break;
            }
        }
    }

    private void handleDropdownSelection() {
        ParsedValueItem selected = (ParsedValueItem) tokenDropdown.getSelectedItem();

        if (selected == null || selected.isCategory()) {
            selectionPreviewLabel.setText("(select a token from the dropdown)");
            applySelectionButton.setEnabled(false);
            updateInjectionPreview();
            return;
        }

        // Skip placeholder items
        if (selected.getSourceType() == null) {
            selectionPreviewLabel.setText("(no valid selection)");
            applySelectionButton.setEnabled(false);
            updateInjectionPreview();
            return;
        }

        // Update preview with full value (truncated if needed)
        String value = selected.getValue();
        String preview = value.length() > 80 ? value.substring(0, 77) + "..." : value;
        selectionPreviewLabel.setText(preview);
        applySelectionButton.setEnabled(true);

        // Update injection preview with new token value
        updateInjectionPreview();
    }

    /**
     * Get the currently selected item, or null if none selected.
     */
    private ParsedValueItem getSelectedItem() {
        ParsedValueItem item = (ParsedValueItem) tokenDropdown.getSelectedItem();
        if (item != null && !item.isCategory() && item.getSourceType() != null) {
            return item;
        }
        return null;
    }

    /**
     * Restore a previous selection by path and source type.
     */
    private void restoreSelection(TokenExtractionConfig.SourceType sourceType, String path) {
        if (sourceType == null || path == null || path.isEmpty()) {
            return;
        }

        for (int i = 0; i < tokenDropdown.getItemCount(); i++) {
            ParsedValueItem item = tokenDropdown.getItemAt(i);
            if (!item.isCategory() &&
                    item.getSourceType() == sourceType &&
                    item.getPath().equals(path)) {
                tokenDropdown.setSelectedIndex(i);
                return;
            }
        }
    }

    private void applySelection() {
        if (currentConfig == null) {
            return;
        }

        ParsedValueItem selected = getSelectedItem();
        if (selected == null) {
            return;
        }

        TokenExtractionConfig extraction = currentConfig.getTokenExtraction();
        extraction.setAutoDetect(false);
        extraction.setSourceType(selected.getSourceType());
        extraction.setSelectionStart(-1);  // Position-based selection no longer used
        extraction.setSelectionEnd(-1);
        extraction.setSelectedValue(selected.getValue());

        if (selected.getSourceType() == TokenExtractionConfig.SourceType.JSON_BODY) {
            extraction.setJsonPath(selected.getPath());
            extraction.setTokenName("");
        } else {
            extraction.setTokenName(selected.getPath());
            extraction.setJsonPath("");
        }

        markDirty();

        JOptionPane.showMessageDialog(this,
                "Token selection applied:\n" +
                        "Source: " + selected.getSourceType() + "\n" +
                        "Path: " + selected.getPath() + "\n" +
                        "Value: " + (selected.getValue().length() > 50
                                ? selected.getValue().substring(0, 47) + "..."
                                : selected.getValue()),
                "Selection Applied",
                JOptionPane.INFORMATION_MESSAGE);
    }

    public void setConfig(HostConfig config) {
        this.currentConfig = config;

        if (config == null) {
            clearFields();
            setEnabled(false);
            return;
        }

        setEnabled(true);

        urlPatternField.setText(config.getUrlPattern());
        requestArea.setText(config.getRawRequest());
        tokenSelectionPanel.setText(config.getRawResponse());

        // Parse response to populate dropdown
        parseResponse();

        // Restore selection if exists
        TokenExtractionConfig extraction = config.getTokenExtraction();
        if (extraction.hasSelection() || !extraction.getSelectedValue().isEmpty()) {
            // Restore selection by path lookup
            String path = extraction.getSourceType() == TokenExtractionConfig.SourceType.JSON_BODY
                    ? extraction.getJsonPath() : extraction.getTokenName();
            restoreSelection(extraction.getSourceType(), path);
        }

        // Token injection
        TokenInjectionConfig injection = config.getTokenInjection();
        injectionAutoDetect.setSelected(injection.isAutoDetect());

        // Select the matching dropdown item
        TokenInjectionConfig.TargetType targetType = injection.getTargetType();
        for (int i = 0; i < injectionTypeDropdown.getItemCount(); i++) {
            if (injectionTypeDropdown.getItemAt(i).type == targetType) {
                injectionTypeDropdown.setSelectedIndex(i);
                break;
            }
        }

        injectionNameField.setText(injection.getTargetName());
        updateInjectionFields();
    }

    public void saveToConfig() {
        if (currentConfig == null) return;

        currentConfig.setUrlPattern(urlPatternField.getText().trim());
        currentConfig.setRawRequest(requestArea.getText());
        currentConfig.setRawResponse(tokenSelectionPanel.getText());

        // Parse request to extract login details
        parseRequestForConfig();

        // Token injection
        TokenInjectionConfig injection = currentConfig.getTokenInjection();
        injection.setAutoDetect(injectionAutoDetect.isSelected());

        InjectionOption selectedOption = (InjectionOption) injectionTypeDropdown.getSelectedItem();
        if (selectedOption != null) {
            injection.setTargetType(selectedOption.type);
        }
        injection.setTargetName(injectionNameField.getText().trim());

        if (onChangeListener != null) {
            onChangeListener.run();
        }
    }

    /**
     * Parse the raw request text to extract login URL, method, content type, and body.
     */
    private void parseRequestForConfig() {
        String requestText = requestArea.getText();
        if (requestText == null || requestText.isEmpty()) {
            return;
        }

        String[] lines = requestText.split("\\r?\\n");
        if (lines.length == 0) {
            return;
        }

        // Parse request line: METHOD PATH HTTP/1.1
        String requestLine = lines[0].trim();
        String[] requestParts = requestLine.split("\\s+");
        if (requestParts.length >= 2) {
            currentConfig.setLoginMethod(requestParts[0]);

            // Build full URL from path and Host header
            String path = requestParts[1];
            String host = "";
            String contentType = "";
            StringBuilder bodyBuilder = new StringBuilder();
            boolean inBody = false;

            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];

                if (!inBody) {
                    if (line.trim().isEmpty()) {
                        inBody = true;
                        continue;
                    }

                    String lineLower = line.toLowerCase();
                    if (lineLower.startsWith("host:")) {
                        host = line.substring(5).trim();
                    } else if (lineLower.startsWith("content-type:")) {
                        contentType = line.substring(13).trim();
                        // Strip charset if present
                        int semicolonIdx = contentType.indexOf(';');
                        if (semicolonIdx > 0) {
                            contentType = contentType.substring(0, semicolonIdx).trim();
                        }
                    }
                } else {
                    if (bodyBuilder.length() > 0) {
                        bodyBuilder.append("\n");
                    }
                    bodyBuilder.append(line);
                }
            }

            // Build login URL
            if (!host.isEmpty()) {
                String scheme = "https://"; // Default to HTTPS
                currentConfig.setLoginUrl(scheme + host + path);
            }

            if (!contentType.isEmpty()) {
                currentConfig.setContentType(contentType);
            }

            currentConfig.setLoginBody(bodyBuilder.toString());
        }
    }

    private void markDirty() {
        // Called when content changes
    }

    private void clearFields() {
        urlPatternField.setText("");
        requestArea.setText("");
        tokenSelectionPanel.setText("");
        tokenDropdown.removeAllItems();
        selectionPreviewLabel.setText("(select a token from the dropdown)");
        applySelectionButton.setEnabled(false);
        injectionAutoDetect.setSelected(true);
        injectionTypeDropdown.setSelectedIndex(0);  // Bearer
        injectionNameField.setText("");
        updateInjectionFields();
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        urlPatternField.setEnabled(enabled);
        requestArea.setEnabled(enabled);
        tokenSelectionPanel.setEnabled(enabled);
        tokenDropdown.setEnabled(enabled);
        reparseButton.setEnabled(enabled);
        injectionAutoDetect.setEnabled(enabled);
        applySelectionButton.setEnabled(enabled && getSelectedItem() != null);

        if (enabled) {
            updateInjectionFields();
        } else {
            injectionTypeDropdown.setEnabled(false);
            injectionNameLabel.setEnabled(false);
            injectionNameField.setEnabled(false);
            injectionPreviewLabel.setEnabled(false);
        }
    }

    private void updateInjectionFields() {
        boolean manual = !injectionAutoDetect.isSelected();
        injectionTypeDropdown.setEnabled(manual);

        if (manual) {
            updateInjectionNameFieldVisibility();
        } else {
            injectionNameLabel.setVisible(false);
            injectionNameField.setVisible(false);
        }

        updateInjectionPreview();
    }

    private void updateInjectionNameFieldVisibility() {
        InjectionOption selected = (InjectionOption) injectionTypeDropdown.getSelectedItem();
        boolean needsName = selected != null &&
                selected.type != TokenInjectionConfig.TargetType.AUTHORIZATION_BEARER;
        injectionNameLabel.setVisible(needsName);
        injectionNameField.setVisible(needsName);
    }

    private void updateInjectionPreview() {
        String tokenValue = getCurrentTokenValue();
        String truncatedToken = truncateToken(tokenValue);

        String preview;
        if (injectionAutoDetect.isSelected()) {
            // Auto-detect: show preview based on extraction source type
            preview = buildAutoDetectPreview(truncatedToken);
        } else {
            // Manual: show preview based on dropdown selection
            preview = buildManualPreview(truncatedToken);
        }

        injectionPreviewLabel.setText(preview);
    }

    private String getCurrentTokenValue() {
        // Try to get the currently selected token value
        ParsedValueItem selected = getSelectedItem();
        if (selected != null && selected.getValue() != null && !selected.getValue().isEmpty()) {
            return selected.getValue();
        }

        // Fall back to the config's stored value
        if (currentConfig != null) {
            String storedValue = currentConfig.getTokenExtraction().getSelectedValue();
            if (storedValue != null && !storedValue.isEmpty()) {
                return storedValue;
            }
        }

        return "{token}";
    }

    private String truncateToken(String token) {
        if (token == null || token.isEmpty()) {
            return "{token}";
        }
        if (token.length() <= 40) {
            return token;
        }
        return token.substring(0, 37) + "...";
    }

    private String buildAutoDetectPreview(String token) {
        // Determine source type from current selection or config
        TokenExtractionConfig.SourceType sourceType = null;

        ParsedValueItem selected = getSelectedItem();
        if (selected != null) {
            sourceType = selected.getSourceType();
        } else if (currentConfig != null) {
            sourceType = currentConfig.getTokenExtraction().getSourceType();
        }

        if (sourceType == null) {
            return "(select a token to see preview)";
        }

        switch (sourceType) {
            case COOKIE:
                String cookieName = getCookieNameFromSelection();
                return "Cookie: " + cookieName + "=" + token;
            case JSON_BODY:
            case HEADER:
            default:
                return "Authorization: Bearer " + token;
        }
    }

    private String getCookieNameFromSelection() {
        ParsedValueItem selected = getSelectedItem();
        if (selected != null && selected.getPath() != null && !selected.getPath().isEmpty()) {
            return selected.getPath();
        }
        if (currentConfig != null) {
            String name = currentConfig.getTokenExtraction().getTokenName();
            if (name != null && !name.isEmpty()) {
                return name;
            }
        }
        return "{name}";
    }

    private String buildManualPreview(String token) {
        InjectionOption selected = (InjectionOption) injectionTypeDropdown.getSelectedItem();
        if (selected == null) {
            return "(select injection type)";
        }

        String name = injectionNameField.getText().trim();
        if (name.isEmpty()) {
            name = "{name}";
        }

        switch (selected.type) {
            case AUTHORIZATION_BEARER:
                return "Authorization: Bearer " + token;
            case COOKIE:
                return "Cookie: " + name + "=" + token;
            case HEADER:
                return name + ": " + token;
            default:
                return "(unknown type)";
        }
    }

    private void testLogin() {
        if (currentConfig == null) {
            JOptionPane.showMessageDialog(this,
                    "No host configuration selected",
                    "Test Login", JOptionPane.WARNING_MESSAGE);
            return;
        }

        saveToConfig();

        // Validate required fields
        if (currentConfig.getLoginUrl().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Login URL is required. Paste a raw HTTP request to set it.",
                    "Test Login", JOptionPane.WARNING_MESSAGE);
            return;
        }

        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

        // Run test in background
        new Thread(() -> {
            String result = authManager.testLogin(currentConfig);
            SwingUtilities.invokeLater(() -> {
                setCursor(Cursor.getDefaultCursor());
                JOptionPane.showMessageDialog(this,
                        result,
                        "Test Login Result",
                        result.startsWith("Success") ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE);
            });
        }).start();
    }

    /**
     * Custom renderer that makes category headers bold and non-selectable looking.
     */
    private static class CategoryAwareRenderer extends BasicComboBoxRenderer {
        @Override
        public Component getListCellRendererComponent(JList list, Object value,
                                                      int index, boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

            if (value instanceof ParsedValueItem) {
                ParsedValueItem item = (ParsedValueItem) value;
                setText(item.getDisplayText());

                if (item.isCategory()) {
                    setFont(getFont().deriveFont(Font.BOLD));
                    setBackground(new Color(230, 230, 230));
                    setForeground(Color.DARK_GRAY);
                } else {
                    setFont(getFont().deriveFont(Font.PLAIN));
                    if (isSelected) {
                        setBackground(list.getSelectionBackground());
                        setForeground(list.getSelectionForeground());
                    } else {
                        setBackground(list.getBackground());
                        setForeground(list.getForeground());
                    }
                }
            }

            return this;
        }
    }

    /**
     * Represents an injection type option for the dropdown.
     */
    private static class InjectionOption {
        final TokenInjectionConfig.TargetType type;
        final String displayText;

        InjectionOption(TokenInjectionConfig.TargetType type, String displayText) {
            this.type = type;
            this.displayText = displayText;
        }

        @Override
        public String toString() {
            return displayText;
        }
    }
}
