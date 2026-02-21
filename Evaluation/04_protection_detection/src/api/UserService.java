package api;

import java.sql.*;
import javax.servlet.http.*;

public class UserService {
    private Connection conn;
    
    public User getUser(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("id");
        
        // PROTECTED: Input validation + whitelist
        if (!userId.matches("^[0-9]+$")) {
            throw new IllegalArgumentException("Invalid ID");
        }
        userId = userId.replaceAll("[^0-9]", "");
        
        // Semgrep still flags this as formatted SQL string
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return null;
    }
}
