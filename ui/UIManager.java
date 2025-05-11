package whoami.ui;

import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class UIManager {
    private final MontoyaApi api;
    private final Config config;
    private final Map<String, JCheckBox> methodCheckboxes = new HashMap<>();
    private JTextField delayField;
    private JTextField extensionsField;

    public UIManager(MontoyaApi api) {
        this.api = api;
        this.config = new Config(methodCheckboxes);
    }

    public JComponent createTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(createBanner(), BorderLayout.NORTH);
        panel.add(createControlPanel(), BorderLayout.CENTER);
        panel.add(createOptionsPanel(), BorderLayout.SOUTH);
        api.userInterface().registerSuiteTab("Whoami", panel);
        return panel;
    }

    private JPanel createBanner() {
        JPanel bannerPanel = new JPanel();
        bannerPanel.setLayout(new BoxLayout(bannerPanel, BoxLayout.Y_AXIS));
        bannerPanel.setBackground(new Color(47, 62, 70));
        bannerPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JLabel titleLabel = new JLabel("Whoami");
        titleLabel.setFont(new Font("VT323", Font.BOLD, 28));
        titleLabel.setForeground(new Color(244, 211, 94));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel authorLabel = new JLabel("by Kasireddy");
        authorLabel.setFont(new Font("Roboto", Font.PLAIN, 16));
        authorLabel.setForeground(Color.WHITE);
        authorLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        bannerPanel.add(titleLabel);
        bannerPanel.add(Box.createVerticalStrut(5));
        bannerPanel.add(authorLabel);

        Border border = BorderFactory.createLineBorder(new Color(244, 211, 94), 1);
        bannerPanel.setBorder(border);
        return bannerPanel;
    }

    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel statusLabel = new JLabel("Extension is OFF");
        JToggleButton toggle = new JToggleButton("OFF");
        toggle.addActionListener(e -> {
            config.setEnabled(toggle.isSelected());
            toggle.setText(config.isEnabled() ? "ON" : "OFF");
            statusLabel.setText(config.isEnabled() ? "Extension is ON" : "Extension is OFF");
        });

        panel.add(toggle, BorderLayout.WEST);
        panel.add(statusLabel, BorderLayout.CENTER);

        JPanel configPanel = new JPanel(new GridLayout(2, 1));
        delayField = new JTextField("0", 5);
        extensionsField = new JTextField("", 15);
        extensionsField.setToolTipText("Enter comma-separated file extensions (e.g., .js,.css,.png)");
        configPanel.add(createInputPanel("Delay between requests (seconds): ", delayField, this::updateDelay));
        configPanel.add(createInputPanel("Skip tests for file extensions (e.g., .js,.css,.png): ", extensionsField, this::updateExtensions));
        panel.add(configPanel, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createInputPanel(String labelText, JTextField field, Runnable updateAction) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        field.addActionListener(e -> updateAction.run());
        field.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    updateAction.run();
                }
            }
        });
        panel.add(new JLabel(labelText));
        panel.add(field);
        return panel;
    }

    private JPanel createOptionsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JLabel("Allowed HTTP Methods:"), BorderLayout.NORTH);
        panel.add(createMethodPanel(), BorderLayout.CENTER);
        panel.add(createTestingOptionsPanel(), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createMethodPanel() {
        JPanel panel = new JPanel(new GridLayout(0, 2));
        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"};
        for (String method : methods) {
            JCheckBox checkbox = new JCheckBox(method, true);
            methodCheckboxes.put(method, checkbox);
            panel.add(checkbox);
        }
        return panel;
    }

    private JPanel createTestingOptionsPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 1));
        JCheckBox sqlInjectionCheckbox = new JCheckBox("Enable SQL Injection Testing");
        sqlInjectionCheckbox.addActionListener(e -> config.getCheckers().put("SQLi", sqlInjectionCheckbox.isSelected()));
        JCheckBox cookieTestingCheckbox = new JCheckBox("Test Cookie Parameters", true);
        cookieTestingCheckbox.addActionListener(e -> config.setTestCookies(cookieTestingCheckbox.isSelected()));
        panel.add(sqlInjectionCheckbox);
        panel.add(cookieTestingCheckbox);
        return panel;
    }

    private void updateDelay() {
        String input = delayField.getText().trim();
        try {
            if (input.isEmpty()) {
                config.setDelayMillis(0);
                delayField.setText("0");
                return;
            }
            double delaySeconds = Double.parseDouble(input);
            if (delaySeconds < 0) {
                delaySeconds = 0;
                delayField.setText("0");
            }
            config.setDelayMillis((long) (delaySeconds * 1000));
        } catch (NumberFormatException e) {
            config.setDelayMillis(0);
            delayField.setText("0");
        }
    }

    private void updateExtensions() {
        String input = extensionsField.getText().trim();
        config.getExcludedExtensions().clear();
        if (!input.isEmpty()) {
            String[] extensions = input.split(",");
            for (String ext : extensions) {
                ext = ext.trim();
                if (!ext.isEmpty()) {
                    if (!ext.startsWith(".")) {
                        ext = "." + ext;
                    }
                    config.getExcludedExtensions().add(ext.toLowerCase());
                }
            }
        }
    }

    public Config getConfig() {
        return config;
    }

    public static class Config {
        private boolean isEnabled = false;
        private long delayMillis = 0;
        private final Set<String> excludedExtensions = new HashSet<>();
        private final Map<String, Boolean> checkers = new HashMap<>();
        private boolean testCookies = true;
        private final Map<String, JCheckBox> methodCheckboxes;

        public Config(Map<String, JCheckBox> methodCheckboxes) {
            this.methodCheckboxes = methodCheckboxes;
        }

        public boolean isEnabled() {
            return isEnabled;
        }

        public void setEnabled(boolean enabled) {
            isEnabled = enabled;
        }

        public long getDelayMillis() {
            return delayMillis;
        }

        public void setDelayMillis(long delayMillis) {
            this.delayMillis = delayMillis;
        }

        public Set<String> getExcludedExtensions() {
            return excludedExtensions;
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

        public boolean isMethodAllowed(String method) {
            JCheckBox checkbox = methodCheckboxes.get(method.toUpperCase());
            return checkbox != null && checkbox.isSelected();
        }
    }
}
