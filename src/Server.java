import cast128.CAST128;
import cast128.Utils;
import database.Database;
import elgamal.ElGamal;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;

public class Server extends Database {

    ElGamal elgamal;
    CAST128 cast;

    public Server () throws IOException, NoSuchAlgorithmException {

        elgamal = new ElGamal("private_key.pk", "public_key.pk");
        cast    = new CAST128(Paths.get("secret_key.pk"));

        System.out.println("[ LOG ] Server started:");
        System.out.println("        [1] ElGamal:");
        System.out.printf("             Elliptic Curve: y^2 = x^3 + %sx + %s, Base: (%s, %s), Prime: %s, %n", elgamal.private_chunk.a, elgamal.private_chunk.b, elgamal.private_chunk.base.x, elgamal.private_chunk.base.y, elgamal.private_chunk.p);
        System.out.println("        [2] CAST-128:");
        System.out.println("            Secret Key: " + cast.encryptionKey + "\n");

        // Remove comment ONLY to generate new keys
        // elgamal.save();
        // cast.save();
    }

    public byte[] provideCAST128key() {
        if(elgamal != null) {
            byte[] key = elgamal.encrypt(cast.encryptionKey);
            System.out.println("[ LOG ] Server has received the request.");
            System.out.printf("[ LOG ] Server encrypted the secret key using a random value k and the public key:%n%s.%n", Utils.toHex(key));
            System.out.println("[ LOG ] Server sent the cipher to the client with the random value k*BasePoint.\n");

            return key;
        }
        return null;
    }

    public void initDatabaseConnection() {
        Database.connect();
    }

    public void closeDatabaseConnection() {
        Database.closeConnection();
    }

    public void executeCommand(String query) {
        execute(query);
    }

    public String getEncryptedPassword(String username) {
        try {
            ResultSet rs = statement.executeQuery(String.format("SELECT encryptedPassword FROM passwords WHERE username = '%s'", username));
            rs.next();
            return rs.getString("encryptedPassword");

        } catch (Exception e) { e.printStackTrace(); }
        return "";
    }

}
