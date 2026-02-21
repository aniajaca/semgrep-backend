package web;
import javax.servlet.http.*;
public class UnsafeRenderer {
public void renderUserProfile(HttpServletRequest request,
                               HttpServletResponse response) throws Exception {
    // User input
    String username = request.getParameter("name");
    
    // VULNERABLE: No encoding
    response.getWriter().println("<h1>Welcome, " + username + "</h1>");
}
}
