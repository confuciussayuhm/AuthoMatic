package authomatic.ui;

import authomatic.config.AuthConfig;
import authomatic.config.HostConfig;
import authomatic.service.ManualInjectionService;
import authomatic.service.ManualInjectionService.HostStatus;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.core.Range;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Provides context menu items for AuthoMatic:
 * - "Send to AuthoMatic" for importing login requests
 * - "Inject Token" submenu for manual token injection
 */
public class ContextMenuProvider implements ContextMenuItemsProvider {

    private final AuthoMaticTab tab;
    private final AuthConfig config;
    private final ManualInjectionService injectionService;

    public ContextMenuProvider(AuthoMaticTab tab, AuthConfig config, ManualInjectionService injectionService) {
        this.tab = tab;
        this.config = config;
        this.injectionService = injectionService;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // Get message editor context if available
        Optional<MessageEditorHttpRequestResponse> editorOptional = event.messageEditorRequestResponse();

        // "Send to AuthoMatic" menu item
        List<HttpRequestResponse> selected = editorOptional
                .map(editor -> List.of(editor.requestResponse()))
                .orElse(event.selectedRequestResponses());

        if (!selected.isEmpty()) {
            JMenuItem sendToItem = new JMenuItem("Send to AuthoMatic");
            sendToItem.addActionListener(e -> {
                HttpRequestResponse reqRes = selected.get(0);
                tab.openImportDialogWithData(reqRes);
            });
            menuItems.add(sendToItem);
        }

        // "Inject Token" submenu - only show if we have editor context with selection
        if (editorOptional.isPresent()) {
            MessageEditorHttpRequestResponse editor = editorOptional.get();
            Optional<Range> selectionOptional = editor.selectionOffsets();

            if (selectionOptional.isPresent() && editor.selectionContext().name().equals("REQUEST")) {
                Range selection = selectionOptional.get();
                if (selection.startIndexInclusive() < selection.endIndexExclusive()) {
                    JMenu injectMenu = buildInjectSubmenu(editor, selection);
                    menuItems.add(injectMenu);
                }
            }
        }

        return menuItems;
    }

    /**
     * Builds the "Inject Token" submenu with available hosts.
     */
    private JMenu buildInjectSubmenu(MessageEditorHttpRequestResponse editor, Range selection) {
        JMenu menu = new JMenu("Inject Token");

        List<HostStatus> hosts = injectionService.getAvailableHosts();

        if (hosts.isEmpty()) {
            JMenuItem noHosts = new JMenuItem("(No hosts configured)");
            noHosts.setEnabled(false);
            menu.add(noHosts);
            return menu;
        }

        for (HostStatus hostStatus : hosts) {
            JMenuItem hostItem = new JMenuItem(hostStatus.getDisplayName());
            hostItem.addActionListener(e -> {
                performInjection(editor, selection, hostStatus);
            });
            menu.add(hostItem);
        }

        return menu;
    }

    /**
     * Performs the token injection when a host is selected.
     */
    private void performInjection(MessageEditorHttpRequestResponse editor, Range selection, HostStatus hostStatus) {
        // Run in background to not block EDT
        new Thread(() -> {
            try {
                HttpRequestResponse reqRes = editor.requestResponse();
                byte[] requestBytes = reqRes.request().toByteArray().getBytes();
                String requestUrl = reqRes.request().url();

                int start = selection.startIndexInclusive();
                int end = selection.endIndexExclusive();

                // Perform the injection
                byte[] modifiedBytes = injectionService.injectToken(
                        requestBytes,
                        start,
                        end,
                        hostStatus.getHostConfig(),
                        requestUrl
                );

                if (modifiedBytes != null) {
                    // Update the editor with the modified request
                    SwingUtilities.invokeLater(() -> {
                        try {
                            editor.setRequest(burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                                    reqRes.request().httpService(),
                                    burp.api.montoya.core.ByteArray.byteArray(modifiedBytes)
                            ));
                        } catch (Exception ex) {
                            showError("Failed to update request: " + ex.getMessage());
                        }
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        showError("Failed to inject token. Check the AuthoMatic logs for details.");
                    });
                }
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    showError("Error during injection: " + ex.getMessage());
                });
            }
        }).start();
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(null, message, "AuthoMatic - Injection Error", JOptionPane.ERROR_MESSAGE);
    }
}
