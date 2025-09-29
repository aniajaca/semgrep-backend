const axios = require('axios');

async function testJavaScanning() {
  const API = 'http://localhost:3000';
  
  console.log('Testing Java Code with Context Inference\n');
  console.log('=========================================\n');
  
  // Java Spring Boot controller with vulnerabilities
  const javaCode = `
package com.example.api;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import javax.servlet.http.HttpServletRequest;
import java.sql.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private Connection dbConnection;
    
    @PostMapping("/login")
    public UserResponse login(@RequestBody LoginRequest request) {
        String username = request.getUsername();
        String password = request.getPassword();
        
        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE username = '" + username + 
                      "' AND password = '" + password + "'";
        
        try {
            Statement stmt = dbConnection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                User user = new User();
                user.setId(rs.getLong("id"));
                user.setEmail(rs.getString("email"));
                user.setFirstName(rs.getString("firstName"));
                user.setLastName(rs.getString("lastName"));
                user.setSocialSecurityNumber(rs.getString("ssn"));
                user.setCreditCardNumber(rs.getString("creditCard"));
                
                // Hardcoded secret
                String jwtSecret = "mySecretKey123";
                String token = generateToken(user, jwtSecret);
                
                return new UserResponse(user, token);
            }
        } catch (SQLException e) {
            // Information disclosure
            return new UserResponse("Database error: " + e.getMessage());
        }
        
        return null;
    }
    
    @GetMapping("/profile/{id}")
    public User getProfile(@PathVariable String id) {
        // Another SQL injection
        String query = "SELECT * FROM users WHERE id = " + id;
        // ... rest of code
        return null;
    }
}

@Entity
@Table(name = "users")
class User {
    @Id
    private Long id;
    
    @Column(name = "email")
    private String email;
    
    @Column(name = "firstName")
    private String firstName;
    
    @Column(name = "lastName")  
    private String lastName;
    
    @Column(name = "ssn")
    private String socialSecurityNumber;
    
    @Column(name = "creditCard")
    private String creditCardNumber;
    
    @Column(name = "dateOfBirth")
    private Date dateOfBirth;
    
    // getters and setters...
}
`;

  try {
    const response = await axios.post(`${API}/scan-code`, {
      code: javaCode,
      language: 'java',
      filename: 'UserController.java',
      manualContext: {
        production: true  // We'll also see what context gets auto-inferred
      }
    });

    console.log('Scan Results:');
    console.log('=============\n');
    
    console.log(`Engine Used: ${response.data.engine}`);
    console.log(`Total Issues Found: ${response.data.findings.length}`);
    console.log(`Profile Used: ${response.data.provenance?.profileId || 'default'}\n`);
    
    // Show context inference results
    console.log('Context Factors Detected:');
    console.log('-------------------------');
    const contextFactors = response.data.summary?.contextFactorsDetected || [];
    if (contextFactors.length > 0) {
      contextFactors.forEach(factor => {
        console.log(`  • ${factor}`);
      });
    } else {
      console.log('  No automatic context detected');
    }
    
    console.log('\nTop Security Issues:');
    console.log('--------------------');
    
    // Show detailed findings
    response.data.findings.slice(0, 5).forEach((finding, i) => {
      console.log(`\n${i + 1}. [${finding.adjustedSeverity || finding.severity}] ${finding.message}`);
      console.log(`   File: ${finding.file}:${finding.startLine}`);
      console.log(`   CWE: ${finding.cwe}`);
      console.log(`   OWASP: ${finding.owasp || 'N/A'}`);
      console.log(`   Base Score (BTS): ${finding.bts || 'N/A'}`);
      console.log(`   Contextual Risk Score (CRS): ${finding.crs || 'N/A'}/100`);
      console.log(`   Priority: ${finding.priority?.priority || finding.priority || 'N/A'}`);
      
      // Show which context factors were applied
      if (finding.appliedFactors && finding.appliedFactors.length > 0) {
        console.log(`   Applied Factors: ${finding.appliedFactors.join(', ')}`);
      }
      
      // Show inferred factors for this specific finding
      if (finding.inferredFactors && finding.inferredFactors.length > 0) {
        console.log(`   Inferred Context: ${finding.inferredFactors.join(', ')}`);
      }
    });
    
    // Overall risk assessment
    console.log('\nOverall Risk Assessment:');
    console.log('------------------------');
    console.log(`Risk Level: ${response.data.overallRisk?.level || 'N/A'}`);
    console.log(`Risk Score: ${response.data.overallRisk?.score?.final || 'N/A'}/100`);
    
    // Show severity distribution
    if (response.data.summary?.severityDistribution) {
      console.log('\nSeverity Distribution:');
      const dist = response.data.summary.severityDistribution;
      console.log(`  Critical: ${dist.critical || 0}`);
      console.log(`  High: ${dist.high || 0}`);
      console.log(`  Medium: ${dist.medium || 0}`);
      console.log(`  Low: ${dist.low || 0}`);
    }
    
  } catch (error) {
    console.error('Scan failed:', error.response?.data || error.message);
    if (error.response?.data?.error) {
      console.error('Error details:', error.response.data.error);
    }
  }
}

testJavaScanning();
