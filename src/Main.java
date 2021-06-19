import cast128.CAST128;
import database.Database;
import elgamal.ElGamal;
import cast128.Utils;

import javax.rmi.CORBA.Util;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

        Server server = new Server();
        Client client = new Client(server);

        server.elgamal = client.sharePublicElGamalData();
        client.secretBytes = server.provideCAST128key();
        client.decryptCAST128key();

        server.initDatabaseConnection();

//      client.insertPassword("pavel","password123456");
        System.out.println("Password: " + client.selectPassword("pavel"));

        server.closeDatabaseConnection();
    }
}
