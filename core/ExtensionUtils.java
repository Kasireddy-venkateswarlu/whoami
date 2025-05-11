package whoami.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ExtensionUtils implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final Logger logger;
    private final VulnerabilityCheckerManager checkerManager;

    public ExtensionUtils(MontoyaApi api, Logger logger, VulnerabilityCheckerManager checkerManager) {
        this.api = api;
        this.logger = logger;
        this.checkerManager = checkerManager;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        if (event.selectedRequestResponses().size() == 1) {
            JMenuItem sqliTestItem = new JMenuItem("Run SQLi Test");
            sqliTestItem.addActionListener(e -> {
                HttpRequestResponse requestResponse = event.selectedRequestResponses().get(0);
                logger.log("CONTEXT", "Running SQLi test from context menu");
                checkerManager.runChecker("SQLi", requestResponse);
            });
            menuItems.add(sqliTestItem);
        }

        return menuItems;
    }
}
