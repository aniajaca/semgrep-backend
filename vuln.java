import java.sql.*;
import java.io.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class LoginServlet extends HttpServlet {

    private String dbUser = "admin";
    private String dbPass = "supersecret";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userInput = request.getParameter("user");

        // SQL Injection risk:
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        try {
            Connection conn = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/mydb", dbUser, dbPass);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                String username = rs.getString("username");
                response.getWriter().println("Hello, " + username);
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // Weak hashing:
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest("sensitive_data".getBytes());
            System.out.println("MD5 Hash: " + bytesToHex(digest));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
