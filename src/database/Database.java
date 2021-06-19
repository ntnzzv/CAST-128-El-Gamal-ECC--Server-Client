package database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import static java.lang.String.format;

public class Database {
    public static Connection conn = null;
    public static Statement statement = null;
    public static void connect() {
         conn = null;
        try {
            // create a connection to the database
            conn = DriverManager.getConnection("jdbc:sqlite:sample.db");
            statement = conn.createStatement();
            statement.setQueryTimeout(30);  // set timeout to 30 sec.

            System.out.println("[ LOG ] Connection to SQLite has been established.");

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void closeConnection(){
        try {
                conn.close();
            System.out.println("[ LOG ] Connection to SQLite has closed.");
            } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

    public static void insertMyKey(String key) throws SQLException {
        statement.executeUpdate(format("INSERT INTO passwords VALUES(%s)", key));
    }

    protected static void execute(String query) {
        try {
            statement.executeUpdate(query);
        } catch (Exception e) { e.printStackTrace(); }
    }
}
