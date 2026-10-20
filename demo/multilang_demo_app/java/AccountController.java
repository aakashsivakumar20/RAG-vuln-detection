package demo.web;

import java.io.*;
import java.sql.*;
import javax.servlet.http.*;

public class AccountController {
    private final Connection conn;
    private final String exportDir = "/var/exports";

    public AccountController(Connection conn) { this.conn = conn; }

    public ResultSet lookupByEmail(String email) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT id, email, role FROM accounts WHERE email = '" + email + "'");
    }

    public ResultSet lookupSafely(String email) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT id, email, role FROM accounts WHERE email = ?");
        ps.setString(1, email);
        return ps.executeQuery();
    }

    public void welcome(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String user = req.getParameter("user");
        resp.getWriter().println("<h1>Welcome back, " + user + "</h1>");
    }

    public byte[] export(String file) throws IOException {
        File f = new File(exportDir + "/" + file);
        return java.nio.file.Files.readAllBytes(f.toPath());
    }

    public Object restore(byte[] blob) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(blob));
        return in.readObject();
    }
}
