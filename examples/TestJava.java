import java.sql.*;

public class TestJava {
    // Уязвимость: SQL Injection
    public void sqlInjection(String userInput) {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        // Уязвимый код
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        ResultSet rs = stmt.executeQuery(query); // Должно обнаружиться как JAVA-SQLI-001
    }

    // Уязвимость: Insecure Deserialization
    public void insecureDeserialization(byte[] data) {
        try {
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(
                new java.io.ByteArrayInputStream(data)
            );
            Object obj = ois.readObject(); // Должно обнаружиться как JAVA-DES-001
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Уязвимость: Path Traversal
    public void pathTraversal(String filename) {
        java.io.File file = new java.io.File("/uploads/" + filename); // Должно обнаружиться как JAVA-PT-001
        // ... операции с файлом
    }

    // Уязвимость: Command Injection
    public void commandInjection(String command) {
        try {
            Runtime.getRuntime().exec("ls " + command); // Должно обнаружиться как JAVA-CMD-001
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Безопасный код
    public void safeSqlQuery(String userInput) {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, userInput); // Безопасно
    }
}