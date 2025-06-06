package whoami.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.swing.SwingUtils;
import whoami.core.ScanDatabaseHelper;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class UIManager {
    private final MontoyaApi api;
    private final Config config;
    private ScanDatabaseHelper dbHelper;

    public UIManager(MontoyaApi api) {
        this.api = api;
        this.config = new Config();
    }

    public Config getConfig() {
        return config;
    }

    public void createTab() {
        SwingUtils swingUtils = api.userInterface().swingUtils();
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Banner with thick orange border
        JLabel bannerLabel = new JLabel("Whoami by kasireddy", SwingConstants.CENTER);
        bannerLabel.setFont(new Font("Arial", Font.BOLD, 18));
        bannerLabel.setForeground(Color.BLACK);
        bannerLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.ORANGE, 3),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        bannerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(bannerLabel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // Top Panel: Toggle and Delay
        JPanel topPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel statusLabel = new JLabel("Extension is OFF");
        JToggleButton toggle = new JToggleButton("OFF");
        toggle.addActionListener(e -> {
            config.setEnabled(toggle.isSelected());
            toggle.setText(config.isEnabled() ? "ON" : "OFF");
            statusLabel.setText(config.isEnabled() ? "Extension is ON" : "Extension is OFF");
            api.logging().logToOutput("Extension toggle set to: " + (config.isEnabled() ? "ON" : "OFF"));
        });

        JTextField delayField = new JTextField("0", 3);
        delayField.getDocument().addDocumentListener((SimpleDocumentListener) e -> {
            try {
                config.setDelayMillis(Integer.parseInt(delayField.getText()) * 1000);
                api.logging().logToOutput("Delay set to: " + config.getDelayMillis() + "ms");
            } catch (NumberFormatException ex) {
                config.setDelayMillis(0);
                api.logging().logToOutput("Invalid delay value, reset to 0ms");
            }
        });

        gbc.gridx = 0;
        gbc.gridy = 0;
        topPanel.add(toggle, gbc);

        gbc.gridx = 1;
        topPanel.add(statusLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        topPanel.add(new JLabel("Delay between requests (seconds):"), gbc);

        gbc.gridx = 1;
        topPanel.add(delayField, gbc);

        mainPanel.add(topPanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // Method Filtering
        JPanel methodPanel = new JPanel(new GridLayout(2, 4, 10, 10));
        methodPanel.setBorder(BorderFactory.createTitledBorder("Allowed HTTP Methods"));
        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"};
        for (String method : methods) {
            JCheckBox checkbox = new JCheckBox(method, true);
            checkbox.addActionListener(e -> {
                config.setMethodAllowed(method, checkbox.isSelected());
                api.logging().logToOutput("Method " + method + " allowed: " + checkbox.isSelected());
            });
            methodPanel.add(checkbox);
        }
        mainPanel.add(methodPanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // Test Options
        JPanel testPanel = new JPanel(new GridBagLayout());
        testPanel.setBorder(BorderFactory.createTitledBorder("Testing Options"));
        GridBagConstraints testGbc = new GridBagConstraints();
        testGbc.insets = new Insets(2, 5, 2, 5);
        testGbc.fill = GridBagConstraints.HORIZONTAL;
        testGbc.anchor = GridBagConstraints.WEST;

        JCheckBox sqlInjectionCheckbox = new JCheckBox("Enable SQL Injection Testing");
        sqlInjectionCheckbox.addActionListener(e -> {
            config.getCheckers().put("SQLi", sqlInjectionCheckbox.isSelected());
            api.logging().logToOutput("SQLi testing enabled: " + sqlInjectionCheckbox.isSelected());
        });

        JCheckBox noSQLICheckbox = new JCheckBox("Enable NoSQL Injection Testing");
        noSQLICheckbox.addActionListener(e -> {
            config.getCheckers().put("NoSQLI", noSQLICheckbox.isSelected());
            api.logging().logToOutput("NoSQLi testing enabled: " + noSQLICheckbox.isSelected());
        });

        JCheckBox xssCheckbox = new JCheckBox("Enable XSS Testing");
        xssCheckbox.addActionListener(e -> {
            config.getCheckers().put("XSS", xssCheckbox.isSelected());
            api.logging().logToOutput("XSS testing enabled: " + xssCheckbox.isSelected());
        });

        JCheckBox cmdiCheckbox = new JCheckBox("Enable Command Injection Testing");
        cmdiCheckbox.addActionListener(e -> {
            config.getCheckers().put("CMDi", cmdiCheckbox.isSelected());
            api.logging().logToOutput("CMDi testing enabled: " + cmdiCheckbox.isSelected());
        });

        JCheckBox ssrfCheckbox = new JCheckBox("Enable SSRF Testing");
        ssrfCheckbox.addActionListener(e -> {
            config.getCheckers().put("SSRF", ssrfCheckbox.isSelected());
            api.logging().logToOutput("SSRF testing enabled: " + ssrfCheckbox.isSelected());
        });

        JCheckBox sstiCheckbox = new JCheckBox("Enable SSTI Testing");
        sstiCheckbox.addActionListener(e -> {
            config.getCheckers().put("SSTI", sstiCheckbox.isSelected());
            api.logging().logToOutput("SSTI testing enabled: " + sstiCheckbox.isSelected());
        });

        JCheckBox xxeCheckbox = new JCheckBox("Enable XXE Testing");
        xxeCheckbox.addActionListener(e -> {
            config.getCheckers().put("XXE", xxeCheckbox.isSelected());
            api.logging().logToOutput("XXE testing enabled: " + xxeCheckbox.isSelected());
        });

        JCheckBox testCookiesCheckbox = new JCheckBox("Test Cookie Parameters");
        testCookiesCheckbox.addActionListener(e -> {
            config.setTestCookies(testCookiesCheckbox.isSelected());
            api.logging().logToOutput("Test Cookie Parameters enabled: " + testCookiesCheckbox.isSelected());
        });

        JCheckBox preventDuplicatesCheckbox = new JCheckBox("Prevent Duplicate Scans", true);
        preventDuplicatesCheckbox.addActionListener(e -> {
            config.setPreventDuplicates(preventDuplicatesCheckbox.isSelected());
            api.logging().logToOutput("Prevent Duplicate Scans enabled: " + preventDuplicatesCheckbox.isSelected());
        });

        JTextArea excludedExtensionsArea = new JTextArea(2, 15);
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
            api.logging().logToOutput("Excluded extensions updated: " + excluded);
        });

        int row = 0;
        testGbc.gridx = 0;
        testGbc.gridy = row++;
        testPanel.add(sqlInjectionCheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(noSQLICheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(xssCheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(cmdiCheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(ssrfCheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(sstiCheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(xxeCheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(testCookiesCheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(preventDuplicatesCheckbox, testGbc);
        testGbc.gridy = row++;
        testPanel.add(new JLabel("Excluded File Extensions (comma-separated):"), testGbc);
        testGbc.gridy = row++;
        testPanel.add(new JScrollPane(excludedExtensionsArea), testGbc);

        mainPanel.add(testPanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // Add Clear DB Button at the bottom with logging
        api.logging().logToOutput("Adding Clear DB button to UI");
        JButton clearDbButton = new JButton("Clear DB");
        clearDbButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        clearDbButton.addActionListener(e -> {
            api.logging().logToOutput("Clear DB button clicked");
            if (dbHelper != null) {
                dbHelper.clearDatabase();
                JOptionPane.showMessageDialog(mainPanel, "Scan database cleared successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(mainPanel, "Database helper not initialized.", "Error", JOptionPane.ERROR_MESSAGE);
                api.logging().logToError("Clear DB button error: Database helper not initialized");
            }
        });
        mainPanel.add(clearDbButton);
        api.logging().logToOutput("Clear DB button added to UI");

        // Wrap mainPanel in a JScrollPane to handle overflow
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        api.userInterface().registerSuiteTab("whoami", scrollPane);
    }

    public void setDbHelper(ScanDatabaseHelper dbHelper) {
        this.dbHelper = dbHelper;
        api.logging().logToOutput("Database helper set in UIManager");
    }

    public static class Config {
        private boolean isEnabled = false;
        private final Map<String, Boolean> allowedMethods = new HashMap<>();
        private final Map<String, Boolean> checkers = new HashMap<>();
        private boolean testCookies = false;
        private Set<String> excludedExtensions = new HashSet<>();
        private long delayMillis = 0;
        private boolean preventDuplicates = true;

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

        public boolean isPreventDuplicates() {
            return preventDuplicates;
        }

        public void setPreventDuplicates(boolean preventDuplicates) {
            this.preventDuplicates = preventDuplicates;
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
