package whoami.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import whoami.checkers.SQLiChecker;
import whoami.checkers.XSSChecker;
import whoami.checkers.CMDInjectionChecker;
import whoami.checkers.SSRFChecker;
import whoami.checkers.SSTIChecker;
import whoami.checkers.XXEChecker;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ExtensionUtils implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final Logger logger;
    private final SQLiChecker sqliChecker;
    private final XSSChecker xssChecker;
    private final CMDInjectionChecker cmdInjectionChecker;
    private final SSRFChecker ssrfChecker;
    private final SSTIChecker sstiChecker;
    private final XXEChecker xxeChecker;

    public ExtensionUtils(MontoyaApi api, Logger logger, SQLiChecker sqliChecker, XSSChecker xssChecker, CMDInjectionChecker cmdInjectionChecker, SSRFChecker ssrfChecker, SSTIChecker sstiChecker, XXEChecker xxeChecker) {
        this.api = api;
        this.logger = logger;
        this.sqliChecker = sqliChecker;
        this.xssChecker = xssChecker;
        this.cmdInjectionChecker = cmdInjectionChecker;
        this.ssrfChecker = ssrfChecker;
        this.sstiChecker = sstiChecker;
        this.xxeChecker = xxeChecker;
        logger.log("CONTEXT", "ContextMenuItemsProvider initialized");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        logger.log("CONTEXT", "Providing context menu items for event: " + event.toString());
        logger.log("CONTEXT", "Selected requests: " + event.selectedRequestResponses().size() +
                ", Has message editor: " + event.messageEditorRequestResponse().isPresent());
        List<Component> menuItems = new ArrayList<>();

        // Handle single selected request from HTTP history or Site map
        if (event.selectedRequestResponses().size() == 1) {
            logger.log("CONTEXT", "Single request selected, adding test menu items");
            HttpRequestResponse requestResponse = event.selectedRequestResponses().get(0);
            addTestMenuItems(menuItems, requestResponse);
        }
        // Handle multiple selected requests (pick the first one)
        else if (event.selectedRequestResponses().size() > 1) {
            logger.log("CONTEXT", "Multiple requests selected (" + event.selectedRequestResponses().size() + "), using first request");
            HttpRequestResponse requestResponse = event.selectedRequestResponses().get(0);
            addTestMenuItems(menuItems, requestResponse);
        }
        // Handle Repeater or message editor context
        else if (event.messageEditorRequestResponse().isPresent()) {
            logger.log("CONTEXT", "Message editor request/response present, adding test menu items");
            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().get().requestResponse();
            addTestMenuItems(menuItems, requestResponse);
        }
        else {
            logger.log("CONTEXT", "No valid request/response found in event, no menu items added");
            logger.log("CONTEXT", "Event details: InvocationType=" + event.invocationType() +
                    ", SelectedIssues=" + event.selectedIssues().size());
        }

        return menuItems;
    }

    private void addTestMenuItems(List<Component> menuItems, HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            logger.log("CONTEXT", "RequestResponse or Request is null, skipping test menu items");
            return;
        }

        // SQLi Test Menu Item
        JMenuItem sqliTestItem = new JMenuItem("Run SQLi Test");
        sqliTestItem.addActionListener(e -> {
            logger.log("CONTEXT", "Running SQLi test from context menu for URL: " + requestResponse.request().url());
            new Thread(() -> sqliChecker.runContextMenuSqliTest(requestResponse)).start();
        });
        menuItems.add(sqliTestItem);

        // XSS Test Menu Item
        JMenuItem xssTestItem = new JMenuItem("Run XSS Test");
        xssTestItem.addActionListener(e -> {
            logger.log("CONTEXT", "Running XSS test from context menu for URL: " + requestResponse.request().url());
            new Thread(() -> xssChecker.runContextMenuXssTest(requestResponse)).start();
        });
        menuItems.add(xssTestItem);

        // CMDi Test Menu Item
        JMenuItem cmdiTestItem = new JMenuItem("Run Command Injection Test");
        cmdiTestItem.addActionListener(e -> {
            logger.log("CONTEXT", "Running Command Injection test from context menu for URL: " + requestResponse.request().url());
            new Thread(() -> cmdInjectionChecker.runContextMenuCmdiTest(requestResponse)).start();
        });
        menuItems.add(cmdiTestItem);

        // SSRF Test Menu Item
        JMenuItem ssrfTestItem = new JMenuItem("Run SSRF Test");
        ssrfTestItem.addActionListener(e -> {
            logger.log("CONTEXT", "Running SSRF test from context menu for URL: " + requestResponse.request().url());
            new Thread(() -> ssrfChecker.runContextMenuSsrfTest(requestResponse)).start();
        });
        menuItems.add(ssrfTestItem);

        // SSTI Test Menu Item
        JMenuItem sstiTestItem = new JMenuItem("Run SSTI Test");
        sstiTestItem.addActionListener(e -> {
            logger.log("CONTEXT", "Running SSTI test from context menu for URL: " + requestResponse.request().url());
            new Thread(() -> sstiChecker.runContextMenuSstiTest(requestResponse)).start();
        });
        menuItems.add(sstiTestItem);

        // XXE Test Menu Item
        JMenuItem xxeTestItem = new JMenuItem("Run XXE Test");
        xxeTestItem.addActionListener(e -> {
            logger.log("CONTEXT", "Running XXE test from context menu for URL: " + requestResponse.request().url());
            new Thread(() -> xxeChecker.runContextMenuXxeTest(requestResponse)).start();
        });
        menuItems.add(xxeTestItem);
    }
}
