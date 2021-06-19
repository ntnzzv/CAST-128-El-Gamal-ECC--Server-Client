package elgamal;

import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

public class ElGamal {

    final BigInteger A = new BigInteger("5");
    final BigInteger B = new BigInteger("10");
    final BigInteger P = new BigInteger("8009");

    ArrayList<Point> generatedPoints;
    byte[] plaintext, cipher;

    String privateKey, publicKey;

    public class DataChunk {
        public BigInteger a, b, p;
        public Point base;
        public Point key;

        DataChunk() {}

        DataChunk(BigInteger a, BigInteger b, BigInteger p, Point base, Point key) {
            this.key = new Point();
            this.a = a;
            this.b = b;
            this.p = p;
            this.base = base;
            this.key = key;
        }

    }

    public DataChunk private_chunk, public_chunk;

    public ElGamal()
    {
        generatedPoints = generateEllipticPoints();

        generatePrivateKey();
        generatePublicKey();

//         System.out.println(private_chunk.key.x);
//         System.out.println(public_chunk.key);
    }

    public ElGamal(String private_key, String public_key) throws IOException {
            byte[] stream;
            Scanner sc;
            stream                  = Files.readAllBytes(Paths.get(private_key));
            privateKey              = new String(stream);

            private_chunk           = new DataChunk();
            private_chunk.base      = new Point();
            private_chunk.key       = new Point();

            sc                      = new Scanner(privateKey);
            private_chunk.a         = sc.nextBigInteger();
            private_chunk.b         = sc.nextBigInteger();
            private_chunk.p         = sc.nextBigInteger();
            private_chunk.base.x    = sc.nextBigInteger();
            private_chunk.base.y    = sc.nextBigInteger();
            private_chunk.key.x     = sc.nextBigInteger();
            sc.close();

            stream                  = Files.readAllBytes(Paths.get(public_key));
            publicKey               = new String(stream);

            public_chunk            = new DataChunk();
            public_chunk.base       = new Point();
            public_chunk.key        = new Point();

            sc                      = new Scanner(publicKey);
            public_chunk.a          = sc.nextBigInteger();
            public_chunk.b          = sc.nextBigInteger();
            public_chunk.p          = sc.nextBigInteger();
            public_chunk.base.x     = sc.nextBigInteger();
            public_chunk.base.y     = sc.nextBigInteger();
            public_chunk.key.x      = sc.nextBigInteger();
            public_chunk.key.y      = sc.nextBigInteger();
            sc.close();;

    }

    BigInteger sqrt(BigInteger n) {
        BigInteger a = BigInteger.ONE;
        BigInteger b = new BigInteger(n.shiftRight(5).add(new BigInteger("8")).toString());
        while(b.compareTo(a) >= 0) {
            BigInteger mid = new BigInteger(a.add(b).shiftRight(1).toString());
            if(mid.multiply(mid).compareTo(n) > 0)
                b = mid.subtract(BigInteger.ONE);
            else
                a = mid.add(BigInteger.ONE);
        }
        return a.subtract(BigInteger.ONE);
    }

    public ArrayList<Point> generateEllipticPoints() {
        ArrayList<Point> result = new ArrayList<>();
        BigInteger y, y2;

        for(BigInteger x = BigInteger.ZERO; x.compareTo(P) < 0; x = x.add(BigInteger.ONE))
        {
            y2 = x.multiply(x).multiply(x).add(A.multiply(x)).add(B);
            y = sqrt(y2);

            if(y.multiply(y).equals(y2)) {
                result.add(new Point(x, y.mod(P)));
                result.add(new Point(x, y.multiply(new BigInteger("-1")).mod(P)));
            }
        }
        return result;
    }

    public BigInteger generatePrivateKey() {
        ECC.setParam(A, B, P, generatedPoints.get(0));

        // This can generate a coefficient number _a_ of 192 bits length (order of 2^192)
        BigInteger bigint = new BigInteger(192, new Random()).mod(P.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        private_chunk = new DataChunk(A, B, P, generatedPoints.get(0), new Point(bigint, BigInteger.ZERO));

        return bigint;
    }

    public Point generatePublicKey() {
        ECC.setParam(A, B, P, generatedPoints.get(0));

        Point bigpoint = ECC.times(private_chunk.key.x, ECC.basePoint);
        public_chunk = new DataChunk(A, B, P, generatedPoints.get(0), bigpoint);

        return bigpoint;
    }

    public String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    public void printCipher() {
        System.out.println(byteArrayToHex(cipher));
    }

    public byte[] encrypt(String message) {
        StringBuilder ciphertextString = new StringBuilder();
        BigInteger k = new BigInteger(192, new Random()).mod(public_chunk.p.subtract(BigInteger.ONE)).add(BigInteger.ONE);

        ECC.setParam(public_chunk.a, public_chunk.b, public_chunk.p, public_chunk.base);
        ciphertextString.append(ECC.times(k, public_chunk.base).toString());
        ciphertextString.append("\n");

        for(byte b : message.getBytes(StandardCharsets.UTF_8))
            ciphertextString.append(ECC.add(ECC.messageToPoint(new BigInteger(String.valueOf(b + 128))), ECC.times(k, public_chunk.key))).append("\n");

        byte[] cipher = ciphertextString.toString().getBytes(StandardCharsets.UTF_8);
        this.cipher = cipher;

        return cipher;
    }

    public String decrypt(byte[] cipher) {
        String ciphertextString = new String(cipher);
        ArrayList<Byte> byteList = new ArrayList<>();
        Scanner scanner = new Scanner(ciphertextString);
        Point firstPoint = new Point(scanner.nextBigInteger(), scanner.nextBigInteger());

        ECC.setParam(private_chunk.a, private_chunk.b, private_chunk.p, private_chunk.base);

        while(scanner.hasNext()) {
            Point secondPoint = new Point(scanner.nextBigInteger(), scanner.nextBigInteger());
            byteList.add(ECC.pointToMessage(ECC.minus(secondPoint, ECC.times(private_chunk.key.x, firstPoint))).subtract(new BigInteger("128")).byteValue());
        }
        scanner.close();
        plaintext = new byte[byteList.size()];
        int i = 0;
        for(Byte ignored : byteList) {
            plaintext[i] = byteList.get(i);
            i++;
        }

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public void save() {
        try {
            // Private key
            FileWriter private_fw = new FileWriter("private_key.pk");
            private_fw.write(A + " " + B + " " + P +"\n");
            private_fw.write(private_chunk.base.x + " " + private_chunk.base.y + "\n");
            private_fw.write(private_chunk.key.x + "\n");
            private_fw.close();


            FileWriter public_fw = new FileWriter("public_key.pk");
            public_fw.write(A + " " + B + " " + P + "\n");
            public_fw.write(public_chunk.base.x + " " + public_chunk.base.y + "\n");
            public_fw.write(public_chunk.key.x + " " + public_chunk.key.y + "\n");
            public_fw.close();

        } catch (Exception ignored) { }
    }

}
