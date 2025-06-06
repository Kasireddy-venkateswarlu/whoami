package whoami;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import whoami.checkers.SQLiChecker;
import whoami.checkers.XSSChecker;
import whoami.checkers.CMDInjectionChecker;
import whoami.checkers.SSRFChecker;
import whoami.checkers.SSTIChecker;
import whoami.checkers.XXEChecker;
import whoami.checkers.NoSQLIChecker;
import whoami.core.CoreModules;
import whoami.core.ExtensionUtils;
import whoami.core.ScanDatabaseHelper;
import whoami.ui.UIManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class WhoamiExtension implements BurpExtension {
    private CoreModules core;
    private SQLiChecker sqliChecker;
    private XSSChecker xssChecker;
    private CMDInjectionChecker cmdiChecker;
    private SSRFChecker ssrfChecker;
    private SSTIChecker sstiChecker;
    private XXEChecker xxeChecker;
    private NoSQLIChecker noSQLIChecker;
    private ExecutorService executorService;
    private ScanDatabaseHelper dbHelper;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Set<String> processingRequests = new HashSet<>();

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("whoami");

        executorService = Executors.newFixedThreadPool(5);

        UIManager uiManager = new UIManager(api);
        uiManager.createTab();
        core = new CoreModules(api, uiManager);
        sqliChecker = new SQLiChecker(core);
        xssChecker = new XSSChecker(core);
        cmdiChecker = new CMDInjectionChecker(core);
        ssrfChecker = new SSRFChecker(core);
        sstiChecker = new SSTIChecker(core);
        xxeChecker = new XXEChecker(core);
        noSQLIChecker = new NoSQLIChecker(core);
        dbHelper = new ScanDatabaseHelper(core.logger);
        uiManager.setDbHelper(dbHelper);

        api.userInterface().registerContextMenuItemsProvider(new ExtensionUtils(api, core.logger, sqliChecker, xssChecker, cmdiChecker, ssrfChecker, sstiChecker, xxeChecker, noSQLIChecker));
        core.logger.logToOutput("Registered context menu provider for SQLi, XSS, CMDi, SSRF, SSTI, XXE, and NoSQLI testing");

        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
            }

            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                if (!core.uiManager.getConfig().isEnabled()) {
                    core.logger.logToOutput("Extension is disabled, allowing request: " + interceptedRequest.url());
                    return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                }

                String url = interceptedRequest.url().toString();
                String method = interceptedRequest.method();
                String requestKey = method + ":" + url + ":" + interceptedRequest.bodyToString().hashCode();

                synchronized (processingRequests) {
                    if (processingRequests.contains(requestKey)) {
                        core.logger.log("HANDLER", "Skipping recursive scan for request: " + requestKey);
                        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                    }
                    processingRequests.add(requestKey);
                }

                try {
                    if (hasExcludedExtension(url, core.uiManager.getConfig().getExcludedExtensions())) {
                        core.logger.logToOutput("Skipping tests for URL with excluded extension: " + url);
                        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                    }

                    if (!core.scopeFilter.isInScope(url)) {
                        core.logger.logToOutput("Dropped OUT-OF-SCOPE request: " + url);
                        return ProxyRequestToBeSentAction.drop();
                    }

                    if (!core.uiManager.getConfig().isMethodAllowed(method)) {
                        core.logger.logToOutput("Dropped request with disallowed method [" + method + "]: " + url);
                        return ProxyRequestToBeSentAction.drop();
                    }

                    core.logger.logToOutput("Allowed " + method + " request in scope: " + url);

                    String endpoint = interceptedRequest.pathWithoutQuery();
                    Set<String> queryParams = new HashSet<>();
                    Set<String> cookieParams = new HashSet<>();
                    Set<String> bodyParams = new HashSet<>();

                    // Extract parameters for all methods
                    for (HttpParameter param : interceptedRequest.parameters()) {
                        core.logger.log("PARAM", "Parameter: " + param.name() + ", Type: " + param.type());
                        if (param.type() == HttpParameterType.URL) {
                            queryParams.add(param.name());
                        } else if (param.type() == HttpParameterType.COOKIE) {
                            cookieParams.add(param.name());
                        } else {
                            bodyParams.add(param.name());
                        }
                    }

                    // Extract JSON parameters for POST/PUT if applicable
                    if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
                        String contentType = interceptedRequest.headerValue("Content-Type");
                        if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                            String body = interceptedRequest.bodyToString();
                            if (!body.isEmpty()) {
                                try {
                                    JsonNode jsonNode = objectMapper.readTree(body);
                                    extractJsonParameters(jsonNode, "", bodyParams);
                                } catch (IOException e) {
                                    core.logger.logError("JSON", "Failed to parse JSON body for parameter extraction: " + e.getMessage());
                                }
                            }
                        }
                    }

                    core.logger.logToOutput("Extracted parameters - Query: " + queryParams + ", Cookies: " + cookieParams + ", Body: " + bodyParams);

                    boolean shouldPreventDuplicates = core.uiManager.getConfig().isPreventDuplicates();
                    boolean testCookies = core.uiManager.getConfig().isTestCookies();
                    core.logger.logToOutput("Test Cookie Parameter enabled: " + testCookies);
                    Set<String> newParams = new HashSet<>();
                    String paramHash = computeParameterHash(queryParams, bodyParams);

                    // Check if the entire request is already scanned
                    if (shouldPreventDuplicates && dbHelper.isRequestScanned(method, endpoint, queryParams, cookieParams, bodyParams, paramHash)) {
                        core.logger.logToOutput("Request already scanned, skipping: " + method + " " + endpoint + ", ParamHash: " + paramHash);
                        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                    }

                    // Combine parameters for scanning
                    newParams.addAll(queryParams);
                    newParams.addAll(bodyParams);
                    if (testCookies) {
                        core.logger.logToOutput("Including cookie parameters for scanning: " + cookieParams);
                        newParams.addAll(cookieParams);
                    }

                    if (shouldPreventDuplicates) {
                        Set<String> storedParams = dbHelper.getStoredParams(method, endpoint, queryParams, cookieParams);
                        core.logger.logToOutput("Stored parameters: " + storedParams);
                        newParams.removeAll(storedParams);
                        core.logger.logToOutput("New parameters to scan: " + newParams);

                        // Force scan if newlastName is present or no stored params
                        if (newParams.isEmpty() && (bodyParams.contains("user.profile.newlastName") || storedParams.isEmpty())) {
                            newParams.addAll(queryParams);
                            newParams.addAll(bodyParams);
                            if (testCookies) {
                                core.logger.logToOutput("Forcing inclusion of cookie parameters: " + cookieParams);
                                newParams.addAll(cookieParams);
                            }
                            core.logger.logToOutput("Forcing scan due to newlastName or empty stored params: " + newParams);
                        }
                    }

                    // Perform SQLi check if enabled
                    if (core.uiManager.getConfig().getCheckers().getOrDefault("SQLi", false) && !newParams.isEmpty()) {
                        core.logger.logToOutput("Submitting SQLi check with parameters: " + newParams);
                        executorService.submit(() -> {
                            try {
                                sqliChecker.checkForSQLi(interceptedRequest, newParams);
                                if (shouldPreventDuplicates) {
                                    dbHelper.storeScannedRequest(method, endpoint, queryParams, cookieParams, bodyParams, paramHash);
                                }
                            } finally {
                                synchronized (processingRequests) {
                                    processingRequests.remove(requestKey);
                                }
                            }
                        });
                    }

                    // Perform XSS check if enabled
                    if (core.uiManager.getConfig().getCheckers().getOrDefault("XSS", false) && !newParams.isEmpty()) {
                        core.logger.logToOutput("Submitting XSS check with parameters: " + newParams);
                        executorService.submit(() -> {
                            try {
                                xssChecker.checkForXSS(interceptedRequest);
                                if (shouldPreventDuplicates) {
                                    dbHelper.storeScannedRequest(method, endpoint, queryParams, cookieParams, bodyParams, paramHash);
                                }
                            } finally {
                                synchronized (processingRequests) {
                                    processingRequests.remove(requestKey);
                                }
                            }
                        });
                    }

                    // Perform CMDi check if enabled
                    if (core.uiManager.getConfig().getCheckers().getOrDefault("CMDi", false) && !newParams.isEmpty()) {
                        core.logger.logToOutput("Submitting CMDi check with parameters: " + newParams);
                        executorService.submit(() -> {
                            try {
                                cmdiChecker.checkForCMDi(interceptedRequest, newParams);
                                if (shouldPreventDuplicates) {
                                    dbHelper.storeScannedRequest(method, endpoint, queryParams, cookieParams, bodyParams, paramHash);
                                }
                            } finally {
                                synchronized (processingRequests) {
                                    processingRequests.remove(requestKey);
                                }
                            }
                        });
                    }

                    // Perform SSRF check if enabled
                    if (core.uiManager.getConfig().getCheckers().getOrDefault("SSRF", false) && !newParams.isEmpty()) {
                        core.logger.logToOutput("Submitting SSRF check with parameters: " + newParams);
                        executorService.submit(() -> {
                            try {
                                ssrfChecker.checkForSSRF(interceptedRequest);
                                if (shouldPreventDuplicates) {
                                    dbHelper.storeScannedRequest(method, endpoint, queryParams, cookieParams, bodyParams, paramHash);
                                }
                            } finally {
                                synchronized (processingRequests) {
                                    processingRequests.remove(requestKey);
                                }
                            }
                        });
                    }

                    // Perform SSTI check if enabled
                    if (core.uiManager.getConfig().getCheckers().getOrDefault("SSTI", false) && !newParams.isEmpty()) {
                        core.logger.logToOutput("Submitting SSTI check with parameters: " + newParams);
                        executorService.submit(() -> {
                            try {
                                sstiChecker.checkForSSTI(interceptedRequest);
                                if (shouldPreventDuplicates) {
                                    dbHelper.storeScannedRequest(method, endpoint, queryParams, cookieParams, bodyParams, paramHash);
                                }
                            } finally {
                                synchronized (processingRequests) {
                                    processingRequests.remove(requestKey);
                                }
                            }
                        });
                    }

                    // Perform XXE check if enabled
                    if (core.uiManager.getConfig().getCheckers().getOrDefault("XXE", false) && !newParams.isEmpty()) {
                        core.logger.logToOutput("Submitting XXE check with parameters: " + newParams);
                        executorService.submit(() -> {
                            try {
                                xxeChecker.checkForXXE(interceptedRequest);
                                if (shouldPreventDuplicates) {
                                    dbHelper.storeScannedRequest(method, endpoint, queryParams, cookieParams, bodyParams, paramHash);
                                }
                            } finally {
                                synchronized (processingRequests) {
                                    processingRequests.remove(requestKey);
                                }
                            }
                        });
                    }

                    // Perform NoSQLI check if enabled
                    if (core.uiManager.getConfig().getCheckers().getOrDefault("NoSQLI", false) && !newParams.isEmpty()) {
                        core.logger.logToOutput("Submitting NoSQLI check with parameters: " + newParams);
                        executorService.submit(() -> {
                            try {
                                noSQLIChecker.checkForNoSQLI(interceptedRequest);
                                if (shouldPreventDuplicates) {
                                    dbHelper.storeScannedRequest(method, endpoint, queryParams, cookieParams, bodyParams, paramHash);
                                }
                            } finally {
                                synchronized (processingRequests) {
                                    processingRequests.remove(requestKey);
                                }
                            }
                        });
                    }

                    if (!core.uiManager.getConfig().getCheckers().getOrDefault("SQLi", false) &&
                        !core.uiManager.getConfig().getCheckers().getOrDefault("XSS", false) &&
                        !core.uiManager.getConfig().getCheckers().getOrDefault("CMDi", false) &&
                        !core.uiManager.getConfig().getCheckers().getOrDefault("SSRF", false) &&
                        !core.uiManager.getConfig().getCheckers().getOrDefault("SSTI", false) &&
                        !core.uiManager.getConfig().getCheckers().getOrDefault("XXE", false) &&
                        !core.uiManager.getConfig().getCheckers().getOrDefault("NoSQLI", false)) {
                        core.logger.logToOutput("No checks submitted. SQLi enabled: " + core.uiManager.getConfig().getCheckers().getOrDefault("SQLi", false) +
                                                ", XSS enabled: " + core.uiManager.getConfig().getCheckers().getOrDefault("XSS", false) +
                                                ", CMDi enabled: " + core.uiManager.getConfig().getCheckers().getOrDefault("CMDi", false) +
                                                ", SSRF enabled: " + core.uiManager.getConfig().getCheckers().getOrDefault("SSRF", false) +
                                                ", SSTI enabled: " + core.uiManager.getConfig().getCheckers().getOrDefault("SSTI", false) +
                                                ", XXE enabled: " + core.uiManager.getConfig().getCheckers().getOrDefault("XXE", false) +
                                                ", NoSQLI enabled: " + core.uiManager.getConfig().getCheckers().getOrDefault("NoSQLI", false) +
                                                ", newParams: " + newParams);
                    }

                } finally {
                    synchronized (processingRequests) {
                        processingRequests.remove(requestKey);
                    }
                }

                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }
        });

        core.logger.logToOutput("whoami extension loaded with SQL injection, XSS, CMD injection, SSRF, SSTI, XXE, NoSQL injection testing, JSON handling, context menu, and duplicate scan prevention.");
    }

    private boolean hasExcludedExtension(String url, Set<String> excludedExtensions) {
        if (excludedExtensions.isEmpty()) {
            return false;
        }
        String lowerUrl = url.toLowerCase();
        for (String ext : excludedExtensions) {
            if (lowerUrl.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private void extractJsonParameters(JsonNode node, String path, Set<String> parameters) {
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String key = entry.getKey();
                String newPath = path.isEmpty() ? key : path + "." + key;
                core.logger.log("JSON", "Extracting parameter: " + newPath);
                JsonNode value = entry.getValue();
                if (value.isObject() || value.isArray()) {
                    extractJsonParameters(value, newPath, parameters);
                } else {
                    parameters.add(newPath);
                }
            });
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                String newPath = path + "[" + i + "]";
                core.logger.log("JSON", "Extracting parameter: " + newPath);
                JsonNode value = node.get(i);
                if (value.isObject() || value.isArray()) {
                    extractJsonParameters(value, newPath, parameters);
                } else {
                    parameters.add(newPath);
                }
            }
        }
    }

    private String computeParameterHash(Set<String> queryParams, Set<String> bodyParams) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            Set<String> allParams = new TreeSet<>(queryParams);
            allParams.addAll(bodyParams);
            String sortedParams = String.join(",", allParams);
            byte[] hash = digest.digest(sortedParams.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            core.logger.logError("HASH", "Failed to compute parameter hash: " + e.getMessage());
            return "";
        }
    }
}
