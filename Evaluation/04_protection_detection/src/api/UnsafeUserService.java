package api;
import java.sql.;
import javax.servlet.http.;
public class UnsafeUserService {
private Connection conn;
public User getUser(HttpServletRequest request) throws SQLException {
    // User input from HTTP request
    String userId = request.getParameter("id");
    
    // VULNERABLE: String concatenation in SQL
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(
        "SELECT * FROM users WHERE id = '" + userId + "'"
    );
    // ... process results
    return null;
}
}
