package whoami.core;

import java.sql.*;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.nio.file.Paths;

public class ScanDatabaseHelper {
    private static final String DB_PATH = Paths.get(System.getProperty("user.home"), "scanned_requests.db").toString();
    private final Logger logger;

    public ScanDatabaseHelper(Logger logger) {
        this.logger = logger;
        try {
            Class.forName("org.sqlite.JDBC");
            logger.log("DB", "SQLite JDBC driver loaded successfully");
        } catch (ClassNotFoundException e) {
            logger.logError("DB", "Failed to load SQLite JDBC driver: " + e.getMessage());
            throw new RuntimeException("SQLite JDBC driver not found", e);
        }
        migrateTable();
    }

    private void migrateTable() {
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            String createSql = "CREATE TABLE IF NOT EXISTS scanned_requests (" +
                               "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                               "method TEXT," +
                               "endpoint TEXT," +
                               "query_params TEXT," +
                               "cookie_params TEXT," +
                               "body_params TEXT," +
                               "param_hash TEXT)";
            stmt.execute(createSql);
            logger.log("DB", "SQLite table 'scanned_requests' created or already exists at: " + DB_PATH);

            ResultSet rs = conn.getMetaData().getColumns(null, null, "scanned_requests", "param_hash");
            if (!rs.next()) {
                stmt.execute("ALTER TABLE scanned_requests ADD COLUMN param_hash TEXT");
                logger.log("DB", "Added param_hash column to scanned_requests table");
            }
        } catch (SQLException e) {
            logger.logError("DB", "Failed to create or migrate SQLite table: " + e.getMessage());
        }
    }

    private Connection connect() throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA busy_timeout = 5000");
        }
        return conn;
    }

    public boolean isRequestScanned(String method, String endpoint,
                                    Set<String> queryParams, Set<String> cookieParams, Set<String> bodyParams, String paramHash) {
        String queryStr = String.join(",", new TreeSet<>(queryParams));
        String cookieStr = String.join(",", new TreeSet<>(cookieParams));
        String bodyStr = String.join(",", new TreeSet<>(bodyParams));

        String sql = "SELECT 1 FROM scanned_requests WHERE method=? AND endpoint=? " +
                     "AND query_params=? AND cookie_params=? AND body_params=? AND param_hash=?";

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, method);
            pstmt.setString(2, endpoint);
            pstmt.setString(3, queryStr);
            pstmt.setString(4, cookieStr);
            pstmt.setString(5, bodyStr);
            pstmt.setString(6, paramHash);

            ResultSet rs = pstmt.executeQuery();
            boolean exists = rs.next();
            logger.log("DB", "Checked request: " + method + " " + endpoint + " | Query: " + queryStr +
                             ", Cookie: " + cookieStr + ", Body: " + bodyStr + ", ParamHash: " + paramHash + " | Exists: " + exists);
            return exists;
        } catch (SQLException e) {
            logger.logError("DB", "Error checking request in database: " + e.getMessage());
            return false;
        }
    }

    public Set<String> getStoredParams(String method, String endpoint,
                                       Set<String> queryParams, Set<String> cookieParams) {
        Set<String> storedParams = new HashSet<>();
        String queryStr = String.join(",", new TreeSet<>(queryParams));
        String cookieStr = String.join(",", new TreeSet<>(cookieParams));

        String sql = "SELECT query_params, body_params FROM scanned_requests WHERE method=? AND endpoint=? " +
                     "AND query_params=? AND cookie_params=?";

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, method);
            pstmt.setString(2, endpoint);
            pstmt.setString(3, queryStr);
            pstmt.setString(4, cookieStr);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                String queryParamsStr = rs.getString("query_params");
                String bodyParamsStr = rs.getString("body_params");
                if (queryParamsStr != null && !queryParamsStr.isEmpty()) {
                    for (String param : queryParamsStr.split(",")) {
                        storedParams.add(param.trim());
                    }
                }
                if (bodyParamsStr != null && !bodyParamsStr.isEmpty()) {
                    for (String param : bodyParamsStr.split(",")) {
                        storedParams.add(param.trim());
                    }
                }
            }
            logger.log("DB", "Retrieved stored parameters for " + method + " " + endpoint + ": " + storedParams);
        } catch (SQLException e) {
            logger.logError("DB", "Error retrieving stored parameters: " + e.getMessage());
        }
        return storedParams;
    }

    public void storeScannedRequest(String method, String endpoint,
                                    Set<String> queryParams, Set<String> cookieParams, Set<String> bodyParams, String paramHash) {
        String queryStr = String.join(",", new TreeSet<>(queryParams));
        String cookieStr = String.join(",", new TreeSet<>(cookieParams));
        String bodyStr = String.join(",", new TreeSet<>(bodyParams));

        String sql = "INSERT INTO scanned_requests (method, endpoint, query_params, cookie_params, body_params, param_hash) " +
                     "VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, method);
            pstmt.setString(2, endpoint);
            pstmt.setString(3, queryStr);
            pstmt.setString(4, cookieStr);
            pstmt.setString(5, bodyStr);
            pstmt.setString(6, paramHash);
            pstmt.executeUpdate();
            logger.log("DB", "Stored request: " + method + " " + endpoint + " | Query: " + queryStr +
                             ", Cookie: " + cookieStr + ", Body: " + bodyStr + ", ParamHash: " + paramHash);
        } catch (SQLException e) {
            logger.logError("DB", "Error storing request in database: " + e.getMessage());
        }
    }

    public void clearDatabase() {
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM scanned_requests");
            stmt.execute("VACUUM");
            logger.log("DB", "Cleared all entries from scanned_requests database at: " + DB_PATH);
        } catch (SQLException e) {
            logger.logError("DB", "Error clearing database: " + e.getMessage());
        }
    }
}
