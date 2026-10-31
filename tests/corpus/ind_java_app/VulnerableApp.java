/*
 * Intentionally Vulnerable Java Application
 * FOR DEMO/TESTING PURPOSES ONLY
 */

package com.example.vulnerable;

import java.sql.*;
import java.security.MessageDigest;
import java.io.*;

public class VulnerableApp {

    // VULNERABILITY: Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-java-1234567890abcdef";

    // VULNERABILITY: SQL Injection
    public User login(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();

        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE username='" + username +
                      "' AND password='" + password + "'";
        ResultSet rs = stmt.executeQuery(query);

        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        return null;
    }

    // VULNERABILITY: Command Injection
    public String executeCommand(String command) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec(command);

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // VULNERABILITY: Weak Cryptography
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // VULNERABILITY: Path Traversal
    public String readFile(String filename) throws IOException {
        // No path validation
        File file = new File("/uploads/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }

    // VULNERABILITY: Insecure Deserialization
    public Object deserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }

    // VULNERABILITY: XXE (XML External Entity)
    public void parseXML(String xmlData) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory dbf =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // XXE vulnerability - no secure processing
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc = db.parse(new ByteArrayInputStream(xmlData.getBytes()));
    }

    // VULNERABILITY: Hardcoded secret in method
    public String getJWTSecret() {
        return "super_secret_jwt_key_12345";
    }

    static class User {
        String username;
        String email;
        User(String username, String email) {
            this.username = username;
            this.email = email;
        }
    }
}
