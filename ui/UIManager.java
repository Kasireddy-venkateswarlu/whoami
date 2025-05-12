package whoami.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.swing.SwingUtils;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class UIManager {
    private final MontoyaApi api;
    private final Config config;

    public UIManager(MontoyaApi api) {
        this.api = api;
        this.config = new Config();
    }

    public Config getConfig() {
        return config;
    }

    public void createTab() {
        SwingUtils swingUtils = api.userInterface().swingUtils();
        JPanel panel = new JPanel(new BorderLayout());

        JLabel statusLabel = new JLabel("Extension is OFF");
        JToggleButton toggle = new JToggleButton("OFF");
        toggle.addActionListener(e -> {
            config.setEnabled(toggle.isSelected());
            toggle.setText(config.isEnabled() ? "ON" : "OFF");
            statusLabel.setText(config.isEnabled() ? "Extension is ON" : "Extension is OFF");
        });

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toggle, BorderLayout.WEST);
        topPanel.add(statusLabel, BorderLayout.CENTER);

        JTextField delayField = new JTextField("0", 5);
        delayField.getDocument().addDocumentListener((SimpleDocumentListener) e -> {
            try {
                config.setDelayMillis(Integer.parseInt(delayField.getText()) * 1000);
            } catch (NumberFormatException ex) {
                config.setDelayMillis(0);
            }
        });
        JPanel delayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        delayPanel.add(new JLabel("Delay between requests (seconds):"));
        delayPanel.add(delayField);

        topPanel.add(delayPanel, BorderLayout.SOUTH);
        panel.add(topPanel, BorderLayout.NORTH);

        JPanel methodPanel = new JPanel(new GridLayout(0, 2));
        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"};
        for (String method : methods) {
            JCheckBox checkbox = new JCheckBox(method, true);
            checkbox.addActionListener(e -> config.setMethodAllowed(method, checkbox.isSelected()));
            methodPanel.add(checkbox);
        }

        JCheckBox sqlInjectionCheckbox = new JCheckBox("Enable SQL Injection Testing");
        sqlInjectionCheckbox.addActionListener(e -> config.getCheckers().put("SQLi", sqlInjectionCheckbox.isSelected()));

        JCheckBox xssCheckbox = new JCheckBox("Enable XSS Testing");
        xssCheckbox.addActionListener(e -> config.getCheckers().put("XSS", xssCheckbox.isSelected()));

        JCheckBox cmdiCheckbox = new JCheckBox("Enable Command Injection Testing");
        cmdiCheckbox.addActionListener(e -> config.getCheckers().put("CMDi", cmdiCheckbox.isSelected()));

        JCheckBox ssrfCheckbox = new JCheckBox("Enable SSRF Testing");
        ssrfCheckbox.addActionListener(e -> config.getCheckers().put("SSRF", ssrfCheckbox.isSelected()));

        JCheckBox testCookiesCheckbox = new JCheckBox("Test Cookie Parameters");
        testCookiesCheckbox.addActionListener(e -> config.setTestCookies(testCookiesCheckbox.isSelected()));

        JTextArea excludedExtensionsArea = new JTextArea(3, 20);
        excludedExtensionsArea.setText(".css,.js,.png,.jpg,.jpeg,.gif,.svg,.ico,.woff,.woff2,.ttf,.eot");
        excludedExtensionsArea.getDocument().addDocumentListener((SimpleDocumentListener) e -> {
            String[] extensions = excludedExtensionsArea.getText().split(",");
            Set<String> excluded = new HashSet<>();
            for (String ext : extensions) {
                ext = ext.trim().toLowerCase();
                if (!ext.isEmpty()) {
                    if (!ext.startsWith(".")) {
                        ext = "." + ext;
                    }
                    excluded.add(ext);
                }
            }
            config.setExcludedExtensions(excluded);
        });

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(new JLabel("Allowed HTTP Methods:"), BorderLayout.NORTH);
        centerPanel.add(methodPanel, BorderLayout.CENTER);
        JPanel testPanel = new JPanel(new GridLayout(9, 1)); // Increased to 9 for SSRF checkbox
        testPanel.add(sqlInjectionCheckbox);
        testPanel.add(xssCheckbox);
        testPanel.add(cmdiCheckbox);
        testPanel.add(ssrfCheckbox);
        testPanel.add(testCookiesCheckbox);
        testPanel.add(new JLabel("Excluded File Extensions (comma-separated):"));
        testPanel.add(new JScrollPane(excludedExtensionsArea));
        centerPanel.add(testPanel, BorderLayout.SOUTH);

        panel.add(centerPanel, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("whoami", panel);
    }

    public static class Config {
        private boolean isEnabled = false;
        private final Map<String, Boolean> allowedMethods = new HashMap<>();
        private final Map<String, Boolean> checkers = new HashMap<>();
        private boolean testCookies = false;
        private Set<String> excludedExtensions = new HashSet<>();
        private long delayMillis = 0;

        public boolean isEnabled() {
            return isEnabled;
        }

        public void setEnabled(boolean enabled) {
            isEnabled = enabled;
        }

        public boolean isMethodAllowed(String method) {
            return allowedMethods.getOrDefault(method.toUpperCase(), true);
        }

        public void setMethodAllowed(String method, boolean allowed) {
            allowedMethods.put(method.toUpperCase(), allowed);
        }

        public Map<String, Boolean> getCheckers() {
            return checkers;
        }

        public boolean isTestCookies() {
            return testCookies;
        }

        public void setTestCookies(boolean testCookies) {
            this.testCookies = testCookies;
        }

        public Set<String> getExcludedExtensions() {
            return excludedExtensions;
        }

        public void setExcludedExtensions(Set<String> excludedExtensions) {
            this.excludedExtensions = excludedExtensions;
        }

        public long getDelayMillis() {
            return delayMillis;
        }

        public void setDelayMillis(long delayMillis) {
            this.delayMillis = delayMillis;
        }
    }

    @FunctionalInterface
    public interface SimpleDocumentListener extends javax.swing.event.DocumentListener {
        void update(javax.swing.event.DocumentEvent e);

        @Override
        default void insertUpdate(javax.swing.event.DocumentEvent e) {
            update(e);
        }

        @Override
        default void removeUpdate(javax.swing.event.DocumentEvent e) {
            update(e);
        }

        @Override
        default void changedUpdate(javax.swing.event.DocumentEvent e) {
            update(e);
        }
    }
}
