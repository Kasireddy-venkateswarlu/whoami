package whoami.core;

import java.sql.*;
import java.util.Set;
import java.util.TreeSet;
import java.nio.file.Paths;

public class ScanDatabaseHelper {
    // Place the database in the user's home directory
    private static final String DB_PATH = Paths.get(System.getProperty("user.home"), "scanned_requests.db").toString();
    private final Logger logger;

    public ScanDatabaseHelper(Logger logger) {
        this.logger = logger;
        // Explicitly load the SQLite JDBC driver
        try {
            Class.forName("org.sqlite.JDBC");
            logger.log("DB", "SQLite JDBC driver loaded successfully");
        } catch (ClassNotFoundException e) {
            logger.logError("DB", "Failed to load SQLite JDBC driver: " + e.getMessage());
            throw new RuntimeException("SQLite JDBC driver not found", e);
        }
        createTableIfNotExists();
    }

    private void createTableIfNotExists() {
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            String sql = "CREATE TABLE IF NOT EXISTS scanned_requests (" +
                         "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                         "method TEXT," +
                         "endpoint TEXT," +
                         "query_params TEXT," +
                         "cookie_params TEXT," +
                         "body_params TEXT)";
            stmt.execute(sql);
            logger.log("DB", "SQLite table 'scanned_requests' created or already exists at: " + DB_PATH);
        } catch (SQLException e) {
            logger.logError("DB", "Failed to create SQLite table: " + e.getMessage());
            throw new RuntimeException("Failed to create SQLite table", e);
        }
    }

    private Connection connect() throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA busy_timeout = 5000"); // 5 seconds
        }
        return conn;
    }

    public boolean isRequestScanned(String method, String endpoint,
                                    Set<String> queryParams, Set<String> cookieParams, Set<String> bodyParams) {
        String queryStr = String.join(",", new TreeSet<>(queryParams));
        String cookieStr = String.join(",", new TreeSet<>(cookieParams));
        String bodyStr = String.join(",", new TreeSet<>(bodyParams));

        String sql = "SELECT 1 FROM scanned_requests WHERE method=? AND endpoint=? " +
                     "AND query_params=? AND cookie_params=? AND body_params=?";

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, method);
            pstmt.setString(2, endpoint);
            pstmt.setString(3, queryStr);
            pstmt.setString(4, cookieStr);
            pstmt.setString(5, bodyStr);

            ResultSet rs = pstmt.executeQuery();
            boolean exists = rs.next();
            logger.log("DB", "Checked request: " + method + " " + endpoint + " | Query: " + queryStr +
                             ", Cookie: " + cookieStr + ", Body: " + bodyStr + " | Exists: " + exists);
            return exists;
        } catch (SQLException e) {
            logger.logError("DB", "Error checking request in database: " + e.getMessage());
            return false;
        }
    }

    public void storeScannedRequest(String method, String endpoint,
                                    Set<String> queryParams, Set<String> cookieParams, Set<String> bodyParams) {
        if (isRequestScanned(method, endpoint, queryParams, cookieParams, bodyParams)) {
            logger.log("DB", "Request already exists in database, skipping storage");
            return;
        }

        String sql = "INSERT INTO scanned_requests (method, endpoint, query_params, cookie_params, body_params) " +
                     "VALUES (?, ?, ?, ?, ?)";

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, method);
            pstmt.setString(2, endpoint);
            pstmt.setString(3, String.join(",", new TreeSet<>(queryParams)));
            pstmt.setString(4, String.join(",", new TreeSet<>(cookieParams)));
            pstmt.setString(5, String.join(",", new TreeSet<>(bodyParams)));
            pstmt.executeUpdate();
            logger.log("DB", "Stored request: " + method + " " + endpoint + " | Query: " + String.join(",", new TreeSet<>(queryParams)) +
                             ", Cookie: " + String.join(",", new TreeSet<>(cookieParams)) + ", Body: " + String.join(",", new TreeSet<>(bodyParams)));
        } catch (SQLException e) {
            logger.logError("DB", "Error storing request in database: " + e.getMessage());
        }
    }

    public void clearDatabase() {
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM scanned_requests");
            logger.log("DB", "Cleared all entries from scanned_requests database");
        } catch (SQLException e) {
            logger.logError("DB", "Error clearing database: " + e.getMessage());
        }
    }
}
