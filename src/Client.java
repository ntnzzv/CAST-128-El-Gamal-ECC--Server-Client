import cast128.CAST128;
import cast128.Utils;
import database.Database;
import elgamal.ElGamal;
import elgamal.Point;

import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

public class Client {

    public byte[] secretBytes;

    private final ElGamal elgamal;
    public CAST128 cast;
    private String secretKey;
    private final Server server;

    public Client(Server server) throws IOException {
        elgamal = new ElGamal("private_key.pk", "public_key.pk");
        this.server = server;

        System.out.println("[ LOG ] Client has established a connection to the server.\n");
    }

    public ElGamal sharePublicElGamalData() {
        ElGamal publicData = new ElGamal();

        publicData.public_chunk.base = elgamal.public_chunk.base;
        publicData.public_chunk.key = elgamal.public_chunk.key;

        publicData.public_chunk.a = elgamal.public_chunk.a;
        publicData.public_chunk.b = elgamal.public_chunk.b;
        publicData.public_chunk.p = elgamal.public_chunk.p;

        System.out.println("[ LOG ] Client is requesting the secret key.");
        System.out.println("[ LOG ] Client generated a private key: " + elgamal.private_chunk.key.x + ".");
        System.out.println("[ LOG ] Client generated a public key:  " + elgamal.public_chunk.key.toPairString() + ".");
        System.out.println("[ LOG ] Client sent the public key to the server.\n");

        return publicData;
    }

    public void decryptCAST128key() {
        secretKey = elgamal.decrypt(secretBytes);
        cast = new CAST128(secretKey);

        System.out.println("[ LOG ] Client has received the cipher.");
        System.out.printf("[ LOG ] Client has decrypted the cipher and found the CAST-128 key: %s.%n%n", secretKey);
    }

    public void insertPassword(String username, String password) {

        ArrayList<Byte> bytes = cast.Encrypt(password.getBytes());
        String cipher = Utils.bytesToHex(bytes);

        System.out.println(cipher);
        server.executeCommand(String.format("INSERT INTO passwords (username, encryptedPassword) VALUES ('%s','%s')", username, cipher));
    }

    public String selectPassword(String username)  {

        String cipher = server.getEncryptedPassword(username);

        byte[] cipherBytes = Utils.hexStringToByteArray(cipher);
        ArrayList<Byte> bytes = new ArrayList<>();

        for(byte b : cipherBytes)
            bytes.add(b);

        return cast.decrypt(bytes);
    }

}
