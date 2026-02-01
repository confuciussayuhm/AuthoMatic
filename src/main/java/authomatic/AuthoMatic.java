package authomatic;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import authomatic.auth.AuthManager;
import authomatic.config.AuthConfig;
import authomatic.config.ConfigManager;
import authomatic.handler.AuthHttpHandler;
import authomatic.service.ManualInjectionService;
import authomatic.ui.AuthoMaticTab;
import authomatic.ui.ContextMenuProvider;
import authomatic.util.Logger;

/**
 * AuthoMatic - Automatic 401 Unauthorized handling for Burp Suite.
 *
 * This extension automatically intercepts 401 responses, performs re-authentication
 * using configured login endpoints, and retries the original request with the new token.
 */
public class AuthoMatic implements BurpExtension {

    private static final String EXTENSION_NAME = "AuthoMatic";

    private MontoyaApi api;
    private Logger logger;
    private ConfigManager configManager;
    private AuthManager authManager;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(EXTENSION_NAME);

        // Initialize logger
        logger = new Logger(api);
        logger.info("AuthoMatic initializing...");

        // Initialize configuration
        configManager = new ConfigManager(api, logger);
        configManager.load();
        AuthConfig config = configManager.getConfig();

        // Initialize auth manager
        authManager = new AuthManager(api, config, logger);

        // Initialize manual injection service
        ManualInjectionService injectionService = new ManualInjectionService(api, config, authManager, logger);

        // Register HTTP handler
        AuthHttpHandler httpHandler = new AuthHttpHandler(config, authManager, logger);
        api.http().registerHttpHandler(httpHandler);
        logger.info("HTTP handler registered");

        // Register UI tab
        AuthoMaticTab tab = new AuthoMaticTab(config, configManager, authManager, logger);
        tab.setInjectionService(injectionService);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab);
        logger.info("UI tab registered");

        // Register context menu provider with injection service
        ContextMenuProvider contextMenuProvider = new ContextMenuProvider(tab, config, injectionService);
        api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);
        logger.info("Context menu provider registered");

        // Register unload handler
        api.extension().registerUnloadingHandler(() -> {
            configManager.save();
            logger.info("AuthoMatic unloaded, configuration saved");
        });

        logger.info("AuthoMatic initialized successfully");
        logger.info("Configured hosts: " + config.getHostConfigs().size());
    }
}
