package web;

import javax.servlet.http.*;
import org.apache.commons.text.StringEscapeUtils;

public class SafeRenderer {
    
    public void renderUserProfile(HttpServletRequest request, 
                                   HttpServletResponse response) throws Exception {
        String username = request.getParameter("name");
        
        // PROTECTED: Apache Commons HTML escaping
        String safeUsername = StringEscapeUtils.escapeHtml4(username);
        
        // Semgrep may still flag direct response writer
        response.getWriter().println("<h1>Welcome, " + safeUsername + "</h1>");
    }
}
