package authomatic.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Panel for displaying raw HTTP response.
 * Token selection has been moved to HostConfigPanel.
 */
public class TokenSelectionPanel extends JPanel {

    private final JTextArea rawResponseArea;
    private String rawResponse = "";

    public TokenSelectionPanel() {
        setLayout(new BorderLayout());

        rawResponseArea = new JTextArea();
        rawResponseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        rawResponseArea.setEditable(false);
        rawResponseArea.setLineWrap(false);

        JScrollPane scroll = new JScrollPane(rawResponseArea);
        add(scroll, BorderLayout.CENTER);
    }

    /**
     * Set the raw response text.
     */
    public void setText(String text) {
        this.rawResponse = text != null ? text : "";
        rawResponseArea.setText(rawResponse);
    }

    /**
     * Get the raw response text.
     */
    public String getText() {
        return rawResponse;
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        rawResponseArea.setEnabled(enabled);
    }
}
