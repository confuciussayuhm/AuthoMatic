package authomatic.ui;

import authomatic.config.HostConfig;
import authomatic.config.TokenExtractionConfig;
import authomatic.util.HttpParser;
import authomatic.util.ImportAnalyzer;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;

/**
 * Dialog for importing login configuration from raw HTTP request/response.
 */
public class ImportDialog extends JDialog {

    private final JTextArea requestArea;
    private final JTextArea responseArea;
    private final JTextField urlPatternField;
    private final JTextArea analysisArea;
    private final JButton importButton;

    private ImportAnalyzer.ImportResult currentAnalysis;
    private HostConfig resultConfig;
    private boolean imported = false;

    public ImportDialog(Window owner) {
        super(owner, "Import Login Configuration", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Request/Response split pane
        JSplitPane inputSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        inputSplit.setResizeWeight(0.5);

        // Request panel
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request (paste raw HTTP request)"));
        requestArea = new JTextArea(10, 60);
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        requestArea.setLineWrap(false);
        requestArea.getDocument().addDocumentListener(new AnalysisListener());
        requestPanel.add(new JScrollPane(requestArea), BorderLayout.CENTER);
        inputSplit.setTopComponent(requestPanel);

        // Response panel
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response (paste raw HTTP response)"));
        responseArea = new JTextArea(10, 60);
        responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        responseArea.setLineWrap(false);
        responseArea.getDocument().addDocumentListener(new AnalysisListener());
        responsePanel.add(new JScrollPane(responseArea), BorderLayout.CENTER);
        inputSplit.setBottomComponent(responsePanel);

        mainPanel.add(inputSplit, BorderLayout.CENTER);

        // Bottom panel with URL pattern and analysis
        JPanel bottomPanel = new JPanel(new BorderLayout(10, 10));

        // URL Pattern input
        JPanel patternPanel = new JPanel(new BorderLayout(5, 0));
        patternPanel.setBorder(BorderFactory.createTitledBorder("URL Pattern (which requests should use this token?)"));
        urlPatternField = new JTextField();
        urlPatternField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        urlPatternField.setToolTipText("e.g., host.com/api/* or *.example.com/**");
        patternPanel.add(urlPatternField, BorderLayout.CENTER);
        JLabel patternHelp = new JLabel("Examples: host.com/api/* (path prefix), *.example.com/** (wildcard host, any path)");
        patternPanel.add(patternHelp, BorderLayout.SOUTH);
        bottomPanel.add(patternPanel, BorderLayout.NORTH);

        // Analysis panel
        JPanel analysisPanel = new JPanel(new BorderLayout());
        analysisPanel.setBorder(BorderFactory.createTitledBorder("Analysis"));
        analysisArea = new JTextArea(6, 60);
        analysisArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        analysisArea.setEditable(false);
        analysisArea.setForeground(UIManager.getColor("TextArea.foreground"));
        analysisArea.setBackground(UIManager.getColor("TextArea.background"));
        analysisPanel.add(new JScrollPane(analysisArea), BorderLayout.CENTER);
        bottomPanel.add(analysisPanel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        buttonPanel.add(cancelButton);

        importButton = new JButton("Import");
        importButton.setEnabled(false);
        importButton.addActionListener(e -> doImport());
        buttonPanel.add(importButton);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);

        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
        setSize(700, 700);
        setLocationRelativeTo(owner);
    }

    /**
     * Run analysis when input changes.
     */
    private void runAnalysis() {
        String requestText = requestArea.getText();
        String responseText = responseArea.getText();

        HttpParser.ParsedRequest request = HttpParser.parseRequest(requestText);
        HttpParser.ParsedResponse response = HttpParser.parseResponse(responseText);

        if (request == null) {
            analysisArea.setText("Paste a valid HTTP request to analyze.");
            importButton.setEnabled(false);
            currentAnalysis = null;
            return;
        }

        currentAnalysis = ImportAnalyzer.analyze(request, response);

        // Update suggested URL pattern if field is empty
        if (urlPatternField.getText().isEmpty() && !currentAnalysis.suggestedUrlPattern.isEmpty()) {
            urlPatternField.setText(currentAnalysis.suggestedUrlPattern);
        }

        // Build analysis display
        StringBuilder sb = new StringBuilder();

        if (currentAnalysis.hasValidConfig()) {
            sb.append("* Login URL: ").append(currentAnalysis.loginUrl).append("\n");
            sb.append("* Method: ").append(currentAnalysis.method);
            if (!currentAnalysis.contentType.isEmpty()) {
                sb.append(", Content-Type: ").append(currentAnalysis.contentType);
            }
            sb.append("\n");

            if (!currentAnalysis.extraHeaders.isEmpty()) {
                sb.append("* Extra headers: ");
                for (String key : currentAnalysis.extraHeaders.keySet()) {
                    sb.append(key);
                    if (key.equalsIgnoreCase("Authorization") && !currentAnalysis.authType.isEmpty()) {
                        sb.append(" (").append(currentAnalysis.authType);
                        if (!currentAnalysis.decodedBasicAuth.isEmpty()) {
                            // Show first part of decoded basic auth
                            String decoded = currentAnalysis.decodedBasicAuth;
                            if (decoded.length() > 20) {
                                decoded = decoded.substring(0, 20) + "...";
                            }
                            sb.append(": ").append(decoded);
                        }
                        sb.append(")");
                    }
                    sb.append(" ");
                }
                sb.append("(will be sent with login)\n");
            }

            if (!currentAnalysis.oauthGrantType.isEmpty()) {
                sb.append("* OAuth grant type: ").append(currentAnalysis.oauthGrantType).append("\n");
            }

            if (currentAnalysis.hasCredentialsInBody) {
                sb.append("* Credentials detected in body (").append(currentAnalysis.credentialFormat);
                sb.append(") - use ${username} and ${password} placeholders\n");
            }

            if (currentAnalysis.hasTokenExtraction()) {
                sb.append("* Token found: ").append(currentAnalysis.extractionSource);
                sb.append(" -> ").append(currentAnalysis.extractionPath);
                if (currentAnalysis.detectedTokenPreview != null && !currentAnalysis.detectedTokenPreview.isEmpty()) {
                    sb.append("\n  Preview: ").append(currentAnalysis.detectedTokenPreview);
                }
                sb.append("\n");
            } else if (response != null) {
                sb.append("* No token detected in response (will use auto-detection)\n");
            } else {
                sb.append("* Paste response to detect token location\n");
            }

            importButton.setEnabled(true);
        } else {
            sb.append("Could not parse request. Check format.");
            importButton.setEnabled(false);
        }

        analysisArea.setText(sb.toString());
    }

    /**
     * Import configuration from analysis.
     */
    private void doImport() {
        if (currentAnalysis == null || !currentAnalysis.hasValidConfig()) {
            return;
        }

        String urlPattern = urlPatternField.getText().trim();
        if (urlPattern.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please enter a URL pattern to specify which requests should use this token.",
                    "URL Pattern Required", JOptionPane.WARNING_MESSAGE);
            urlPatternField.requestFocus();
            return;
        }

        resultConfig = new HostConfig();
        resultConfig.setUrlPattern(urlPattern);
        resultConfig.setLoginUrl(currentAnalysis.loginUrl);
        resultConfig.setLoginMethod(currentAnalysis.method);
        resultConfig.setContentType(currentAnalysis.contentType);
        resultConfig.setLoginBody(currentAnalysis.loginBody);
        resultConfig.setExtraHeaders(currentAnalysis.extraHeaders);
        resultConfig.setRawRequest(requestArea.getText());
        resultConfig.setRawResponse(responseArea.getText());

        // Set token extraction config if detected
        if (currentAnalysis.hasTokenExtraction()) {
            TokenExtractionConfig extraction = new TokenExtractionConfig();
            extraction.setAutoDetect(false);
            extraction.setSourceType(currentAnalysis.extractionSource);

            if (currentAnalysis.extractionSource == TokenExtractionConfig.SourceType.JSON_BODY) {
                extraction.setJsonPath(currentAnalysis.extractionPath);
            } else {
                extraction.setTokenName(currentAnalysis.extractionPath);
            }

            resultConfig.setTokenExtraction(extraction);
        }

        imported = true;
        dispose();
    }

    /**
     * Check if import was completed.
     */
    public boolean isImported() {
        return imported;
    }

    /**
     * Get the imported configuration.
     */
    public HostConfig getResultConfig() {
        return resultConfig;
    }

    /**
     * Pre-populate the request and response fields with data.
     * Used when sending request/response from context menu.
     */
    public void setRequestResponse(String requestText, String responseText) {
        requestArea.setText(requestText);
        if (responseText != null && !responseText.isEmpty()) {
            responseArea.setText(responseText);
        }
        // Analysis will run automatically via document listeners
    }

    /**
     * Document listener to trigger analysis on text changes.
     */
    private class AnalysisListener implements DocumentListener {
        @Override
        public void insertUpdate(DocumentEvent e) {
            SwingUtilities.invokeLater(ImportDialog.this::runAnalysis);
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            SwingUtilities.invokeLater(ImportDialog.this::runAnalysis);
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            SwingUtilities.invokeLater(ImportDialog.this::runAnalysis);
        }
    }
}
