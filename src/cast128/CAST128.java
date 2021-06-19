package cast128;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class CAST128 {
    public String encryptionKey;
    private String fullplaintext="";
    private Key key = new Key();
    private byte[] plaintext = new byte[8];
    private byte[] data = new byte[8];


    private static final int[] S1 = Sbox.S1;
    private static final int[] S2 = Sbox.S2;
    private static final int[] S3 = Sbox.S3;
    private static final int[] S4 = Sbox.S4;
    private static final int[] S5 = Sbox.S5;
    private static final int[] S6 = Sbox.S6;
    private static final int[] S7 = Sbox.S7;
    private static final int[] S8 = Sbox.S8;


   public static void main(String[] args) throws NoSuchAlgorithmException {

       try {
           CAST128 a = new CAST128();
           ArrayList<Byte>b = a.Encrypt("12345678".getBytes());
           String decrypted = a.decrypt(b);
           System.out.println("encrypted data: " + b);
           System.out.println("Decrypted data: " + decrypted);
       }catch(Exception ignored){};

    }


    public CAST128() {
       try {
           KeyGenerator gen = KeyGenerator.getInstance("AES");//set 128 bit secret key
           gen.init(128); /* 128-bit AES */
           SecretKey secret = gen.generateKey();
           byte[] binary = secret.getEncoded();
           String encryptionKey = Utils.toHex(binary);

           this.encryptionKey = encryptionKey;
           generatePrivateKeys();
       } catch (Exception e) { e.printStackTrace(); }

   }

    public CAST128(String secretKey) {
       this.encryptionKey = secretKey;
        generatePrivateKeys();

    }

    public CAST128(Path secretKeyPath) throws IOException {
        byte[] stream = Files.readAllBytes(secretKeyPath);
        this.encryptionKey = new String(stream);
        generatePrivateKeys();
    }
    
    public ArrayList<Byte> Encrypt(byte[] data) {

        byte[] data8byte= new byte[8];
        byte[] copydata = new byte[8];
        byte[] copyWithPadding;
        byte[] newdata = null;
        ArrayList<Byte> encryptedData = new ArrayList<>();


        Integer padding = 8 - data.length % 8;

        for(int i = 0 ; i < 8 ; i++){
            copydata[i] = padding.byteValue();
        }
        copyWithPadding = copydata.clone();
        this.data = data;
        // Padding datas smaller than 8 bytes
        if(data.length<8)
        {
            System.arraycopy(data, 0, copydata, 0, data.length);
            byte[] encryptByteArray = encryptLogic(copydata);
            for(byte b : encryptByteArray) encryptedData.add(b);
        }

        else{
        if(data.length % 8 == 0){
            newdata = new byte[data.length + 8];
            System.arraycopy(data,0,newdata,0,data.length);
            System.arraycopy(copyWithPadding,0,newdata,data.length,copyWithPadding.length);
        }
        else {
            newdata = new byte[data.length + padding];
            System.arraycopy(data,0,newdata,0,data.length);
            System.arraycopy(copyWithPadding,0,newdata,data.length,padding);
        }

        // Split data longer than 8 bytes
            for(int j=0;j<newdata.length;j++)
            {
                data8byte[j%8]=newdata[j];
                if((j+1) % 8 == 0 || j+1 == newdata.length) // send to decrypt each 8 bytes
                {
                    // padding for data smaller than 8 bytes
                    System.arraycopy(data8byte, 0, copydata, 0, data8byte.length);

                    byte[] encryptByteArray = encryptLogic(copydata);
                    for(byte b : encryptByteArray) encryptedData.add(b);

                    data8byte = new byte[8];
                    copydata = copyWithPadding.clone();
                }
            }
        }
        return encryptedData;
    }

    private byte[] encryptLogic(byte[] data){

        byte[] result = new byte[8];

        int L = ByteBuffer.wrap(data, 0, 4).getInt();
        int R = ByteBuffer.wrap(data, 4, 4).getInt();


        L ^= f1(R, key.getKm(0 ), key.getKr(0 ));
        R ^= f2(L, key.getKm(1 ), key.getKr(1 )); // round 2
        L ^= f3(R, key.getKm(2 ), key.getKr(2 ));
        R ^= f1(L, key.getKm(3 ), key.getKr(3 )); // round 4
        L ^= f2(R, key.getKm(4 ), key.getKr(4 ));
        R ^= f3(L, key.getKm(5 ), key.getKr(5 )); // round 6
        L ^= f1(R, key.getKm(6 ), key.getKr(6 ));
        R ^= f2(L, key.getKm(7 ), key.getKr(7 )); // round 8
        L ^= f3(R, key.getKm(8 ), key.getKr(8 ));
        R ^= f1(L, key.getKm(9 ), key.getKr(9 )); // round 10
        L ^= f2(R, key.getKm(10), key.getKr(10));
        R ^= f3(L, key.getKm(11), key.getKr(11)); // round 12
        L ^= f1(R, key.getKm(12), key.getKr(12));
        R ^= f2(L, key.getKm(13), key.getKr(13)); // round 14
        L ^= f3(R, key.getKm(14), key.getKr(14));
        R ^= f1(L, key.getKm(15), key.getKr(15)); // round 16


        unscramble(R, result, 0, 4);
        unscramble(L, result, 4, 8);

        return result;
    }

    private static String hexToBin(String hex){
        String bin = "";
        String binFragment = "";
        int iHex;
        hex = hex.trim();
        hex = hex.replaceFirst("0x", "");

        for(int i = 0; i < hex.length(); i++){
            iHex = Integer.parseInt(""+hex.charAt(i),16);
            binFragment = Integer.toBinaryString(iHex);

            while(binFragment.length() < 4){
                binFragment = "0" + binFragment;
            }
            bin += binFragment;
        }
        return bin;
    }

    private void generatePrivateKeys() {
        Integer[] xValues = new Integer[16];

        String x0x1x2x3 = encryptionKey.substring(0,8);
        String x4x5x6x7 = encryptionKey.substring(8,16);
        String x8x9xAxB = encryptionKey.substring(16,24);
        String xCxDxExF = encryptionKey.substring(24,32);


        xValues[0]= Integer.parseInt(hexToBin(x0x1x2x3).substring(0, 8),2);
        xValues[1]= Integer.parseInt(hexToBin(x0x1x2x3).substring(8, 16),2);
        xValues[2]= Integer.parseInt(hexToBin(x0x1x2x3).substring(16, 24),2);
        xValues[3]= Integer.parseInt(hexToBin(x0x1x2x3).substring(24, 32),2);
        xValues[4]= Integer.parseInt(hexToBin(x4x5x6x7).substring(0, 8),2);
        xValues[5]= Integer.parseInt(hexToBin(x4x5x6x7).substring(8, 16),2);
        xValues[6]= Integer.parseInt(hexToBin(x4x5x6x7).substring(16, 24),2);
        xValues[7]= Integer.parseInt(hexToBin(x4x5x6x7).substring(24, 32),2);
        xValues[8]= Integer.parseInt(hexToBin(x8x9xAxB).substring(0, 8),2);
        xValues[9]= Integer.parseInt(hexToBin(x8x9xAxB).substring(8, 16),2);
        xValues[10]= Integer.parseInt(hexToBin(x8x9xAxB).substring(16, 24),2);
        xValues[11]= Integer.parseInt(hexToBin(x8x9xAxB).substring(24, 32),2);
        xValues[12]= Integer.parseInt(hexToBin(xCxDxExF).substring(0, 8),2);
        xValues[13]= Integer.parseInt(hexToBin(xCxDxExF).substring(8, 16),2);
        xValues[14]= Integer.parseInt(hexToBin(xCxDxExF).substring(16, 24),2);
        xValues[15]= Integer.parseInt(hexToBin(xCxDxExF).substring(24, 32),2);

        byte[] z = new byte[16];//z0z1z2z3
        byte[] x = new byte[16];//x0x1x2x3


        int z0z1z2z3, z4z5z6z7, z8z9zAzB, zCzDzEzF;


        int x0x1x2x3I = ByteBuffer.wrap(x, 0, 4).getInt();
        int x4x5x6x7I = ByteBuffer.wrap(x, 4, 4).getInt();
        int x8x9xAxBI = ByteBuffer.wrap(x, 8, 4).getInt();
        int xCxDxExFI = ByteBuffer.wrap(x, 12, 4).getInt();

        z0z1z2z3 = x0x1x2x3I ^ S5[getUnsignedInt(x[13])] ^ S6[getUnsignedInt(x[15])] ^ S7[getUnsignedInt(x[12])] ^ S8[getUnsignedInt(x[14])] ^ S7[getUnsignedInt(x[8])];
        unscramble(z0z1z2z3, z, 0, 4);
        z4z5z6z7 = x8x9xAxBI ^ S5[getUnsignedInt(z[0])] ^ S6[getUnsignedInt(z[2])] ^ S7[getUnsignedInt(z[1])] ^ S8[getUnsignedInt(z[3])] ^ S8[getUnsignedInt(x[10])];
        unscramble(z4z5z6z7, z, 4, 8);
        z8z9zAzB = xCxDxExFI ^ S5[getUnsignedInt(z[7])] ^ S6[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[5])] ^ S8[getUnsignedInt(z[4])] ^ S5[getUnsignedInt(x[9])];
        unscramble(z8z9zAzB, z, 8, 12);
        zCzDzEzF = x4x5x6x7I ^ S5[getUnsignedInt(z[10])] ^ S6[getUnsignedInt(z[9])] ^ S7[getUnsignedInt(z[11])] ^ S8[getUnsignedInt(z[8])] ^ S6[getUnsignedInt(x[15])];
        unscramble(zCzDzEzF,z,12,16);







        key.setK(0, S5[getUnsignedInt(z[8])] ^ S6[getUnsignedInt(z[9])] ^ S7[getUnsignedInt(z[7])] ^ S8[getUnsignedInt(z[6])] ^ S5[getUnsignedInt(z[2])]);
        key.setK(1, S5[getUnsignedInt(z[10])] ^ S6[getUnsignedInt(z[11])] ^ S7[getUnsignedInt(z[5])] ^ S8[getUnsignedInt(z[4])] ^ S6[getUnsignedInt(z[6])]);
        key.setK(2, S5[getUnsignedInt(z[12])] ^ S6[getUnsignedInt(z[13])] ^ S7[getUnsignedInt(z[3])] ^ S8[getUnsignedInt(z[2])] ^ S7[getUnsignedInt(z[9])]);
        key.setK(3, S5[getUnsignedInt(z[14])] ^ S6[getUnsignedInt(z[15])] ^ S7[getUnsignedInt(z[1])] ^ S8[getUnsignedInt(z[0])] ^ S8[getUnsignedInt(z[12])]);

        x0x1x2x3I = z8z9zAzB ^ S5[getUnsignedInt(z[5])] ^ S6[getUnsignedInt(z[7])] ^ S7[getUnsignedInt(z[4])] ^ S8[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[0])];
        unscramble(x0x1x2x3I,x,0,4);

        x4x5x6x7I = z0z1z2z3 ^ S5[getUnsignedInt(x[0])] ^ S6[getUnsignedInt(x[2])] ^ S7[getUnsignedInt(x[1])] ^ S8[getUnsignedInt(x[3])] ^ S8[getUnsignedInt(z[2])];
        unscramble(x4x5x6x7I, x, 4, 8);

        x8x9xAxBI = z4z5z6z7 ^ S5[getUnsignedInt(x[7])] ^ S6[getUnsignedInt(x[6])] ^ S7[getUnsignedInt(x[5])] ^ S8[getUnsignedInt(x[4])] ^ S5[getUnsignedInt(z[1])];
        unscramble(x8x9xAxBI, x, 8, 12);

        xCxDxExFI = zCzDzEzF ^ S5[getUnsignedInt(x[10])] ^ S6[getUnsignedInt(x[9])] ^ S7[getUnsignedInt(x[11])] ^ S8[getUnsignedInt(x[8])] ^ S6[getUnsignedInt(z[3])];
        unscramble(xCxDxExFI, x, 12, 16);



        key.setK(4, S5[getUnsignedInt(x[3])] ^ S6[getUnsignedInt(x[2])] ^ S7[getUnsignedInt(x[12])] ^ S8[getUnsignedInt(x[13])] ^ S5[getUnsignedInt(x[8])]);
        key.setK(5,  S5[getUnsignedInt(x[1])] ^ S6[getUnsignedInt(x[0])] ^ S7[getUnsignedInt(x[14])] ^ S8[getUnsignedInt(x[15])] ^ S6[getUnsignedInt(x[13])]);
        key.setK(6, S5[getUnsignedInt(x[7])] ^ S6[getUnsignedInt(x[6])] ^ S7[getUnsignedInt(x[8])] ^ S8[getUnsignedInt(x[9])] ^ S7[getUnsignedInt(x[3])]);
        key.setK(7, S5[getUnsignedInt(x[5])] ^ S6[getUnsignedInt(x[4])] ^ S7[getUnsignedInt(x[10])] ^ S8[getUnsignedInt(x[11])] ^ S8[getUnsignedInt(x[7])]);

        z0z1z2z3 = x0x1x2x3I ^ S5[getUnsignedInt(x[13])] ^ S6[getUnsignedInt(x[15])] ^ S7[getUnsignedInt(x[12])] ^ S8[getUnsignedInt(x[14])] ^ S7[getUnsignedInt(x[8])];
        unscramble(z0z1z2z3, z, 0, 4);
        z4z5z6z7 = x8x9xAxBI ^ S5[getUnsignedInt(z[0])] ^ S6[getUnsignedInt(z[2])] ^ S7[getUnsignedInt(z[1])] ^ S8[getUnsignedInt(z[3])] ^ S8[getUnsignedInt(x[10])];
        unscramble(z4z5z6z7, z, 4, 8);
        z8z9zAzB = xCxDxExFI ^ S5[getUnsignedInt(z[7])] ^ S6[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[5])] ^ S8[getUnsignedInt(z[4])] ^ S5[getUnsignedInt(x[9])];
        unscramble(z8z9zAzB, z, 8, 12);
        zCzDzEzF = x4x5x6x7I ^ S5[getUnsignedInt(z[10])] ^ S6[getUnsignedInt(z[9])] ^ S7[getUnsignedInt(z[11])] ^ S8[getUnsignedInt(z[8])] ^ S6[getUnsignedInt(x[11])];
        unscramble(zCzDzEzF, z, 12, 16);



        key.setK(8, S5[getUnsignedInt(z[3])] ^ S6[getUnsignedInt(z[2])] ^ S7[getUnsignedInt(z[12])] ^ S8[getUnsignedInt(z[13])] ^ S5[getUnsignedInt(z[9])]);
        key.setK(9, S5[getUnsignedInt(z[1])] ^ S6[getUnsignedInt(z[0])] ^ S7[getUnsignedInt(z[14])] ^ S8[getUnsignedInt(z[15])] ^ S6[getUnsignedInt(z[12])]);
        key.setK(10, S5[getUnsignedInt(z[7])] ^ S6[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[8])] ^ S8[getUnsignedInt(z[9])] ^ S7[getUnsignedInt(z[2])]);
        key.setK(11, S5[getUnsignedInt(z[5])] ^ S6[getUnsignedInt(z[4])] ^ S7[getUnsignedInt(z[10])] ^ S8[getUnsignedInt(z[11])] ^ S8[getUnsignedInt(z[6])]);

        x0x1x2x3I = z8z9zAzB ^ S5[getUnsignedInt(z[5])] ^ S6[getUnsignedInt(z[7])] ^ S7[getUnsignedInt(z[4])] ^ S8[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[0])];
        unscramble(x0x1x2x3I, x, 0, 4);
        x4x5x6x7I = z0z1z2z3 ^ S5[getUnsignedInt(x[0])] ^ S6[getUnsignedInt(x[2])] ^ S7[getUnsignedInt(x[1])] ^ S8[getUnsignedInt(x[3])] ^ S8[getUnsignedInt(z[2])];
        unscramble(x4x5x6x7I, x,4, 8);
        x8x9xAxBI = z4z5z6z7 ^ S5[getUnsignedInt(x[7])] ^ S6[getUnsignedInt(x[6])] ^ S7[getUnsignedInt(x[5])] ^ S8[getUnsignedInt(x[4])] ^ S5[getUnsignedInt(z[1])];
        unscramble(x8x9xAxBI, x, 8, 12);
        xCxDxExFI = zCzDzEzF ^ S5[getUnsignedInt(x[10])] ^ S6[getUnsignedInt(x[9])] ^ S7[getUnsignedInt(x[11])] ^ S8[getUnsignedInt(x[8])] ^ S6[getUnsignedInt(z[3])];
        unscramble(xCxDxExFI, x, 12, 16);



        key.setK(12, S5[getUnsignedInt(x[8])] ^ S6[getUnsignedInt(x[9])] ^ S7[getUnsignedInt(x[7])] ^ S8[getUnsignedInt(x[6])] ^ S5[getUnsignedInt(x[3])]);
        key.setK(13, S5[getUnsignedInt(x[10])] ^ S6[getUnsignedInt(x[11])] ^ S7[getUnsignedInt(x[5])] ^ S8[getUnsignedInt(x[4])] ^ S6[getUnsignedInt(x[7])]);
        key.setK(14, S5[getUnsignedInt(x[12])] ^ S6[getUnsignedInt(x[13])] ^ S7[getUnsignedInt(x[3])] ^ S8[getUnsignedInt(x[2])] ^ S7[getUnsignedInt(x[8])]);
        key.setK(15, S5[getUnsignedInt(x[14])] ^ S6[getUnsignedInt(x[15])] ^ S7[getUnsignedInt(x[1])] ^ S8[getUnsignedInt(x[0])] ^ S8[getUnsignedInt(x[13])]);

        z0z1z2z3 = x0x1x2x3I ^ S5[getUnsignedInt(x[13])] ^ S6[getUnsignedInt(x[15])] ^ S7[getUnsignedInt(x[12])] ^ S8[getUnsignedInt(x[14])] ^ S7[getUnsignedInt(x[8])];
        unscramble(z0z1z2z3, z, 0, 4);
        z4z5z6z7 = x8x9xAxBI ^ S5[getUnsignedInt(z[0])] ^ S6[getUnsignedInt(z[2])] ^ S7[getUnsignedInt(z[1])] ^ S8[getUnsignedInt(z[3])] ^ S8[getUnsignedInt(x[10])];
        unscramble(z4z5z6z7, z, 4, 8);
        z8z9zAzB = xCxDxExFI ^ S5[getUnsignedInt(z[7])] ^ S6[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[5])] ^ S8[getUnsignedInt(z[4])] ^ S5[getUnsignedInt(x[9])];
        unscramble(z8z9zAzB, z, 8, 12);
        zCzDzEzF = x4x5x6x7I ^ S5[getUnsignedInt(z[10])] ^ S6[getUnsignedInt(z[9])] ^ S7[getUnsignedInt(z[11])] ^ S8[getUnsignedInt(z[8])] ^ S6[getUnsignedInt(x[11])];
        unscramble(zCzDzEzF, z, 12, 16);

        key.setK(16, S5[getUnsignedInt(z[8])] ^ S6[getUnsignedInt(z[9])] ^ S7[getUnsignedInt(z[7])] ^ S8[getUnsignedInt(z[6])] ^ S5[getUnsignedInt(z[2])]);
        key.setK(17, S5[getUnsignedInt(z[10])] ^ S6[getUnsignedInt(z[11])] ^ S7[getUnsignedInt(z[5])] ^ S8[getUnsignedInt(z[4])] ^ S6[getUnsignedInt(z[6])]);
        key.setK(18,  S5[getUnsignedInt(z[12])] ^ S6[getUnsignedInt(z[13])] ^ S7[getUnsignedInt(z[3])] ^ S8[getUnsignedInt(z[2])] ^ S7[getUnsignedInt(z[9])]);
        key.setK(19, S5[getUnsignedInt(z[14])] ^ S6[getUnsignedInt(z[15])] ^ S7[getUnsignedInt(z[1])] ^ S8[getUnsignedInt(z[0])] ^ S8[getUnsignedInt(z[12])]);

        x0x1x2x3I = z8z9zAzB ^ S5[getUnsignedInt(z[5])] ^ S6[getUnsignedInt(z[7])] ^ S7[getUnsignedInt(z[4])] ^ S8[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[0])];
        unscramble(x0x1x2x3I, x, 0, 4);
        x4x5x6x7I = z0z1z2z3 ^ S5[getUnsignedInt(x[0])] ^ S6[getUnsignedInt(x[2])] ^ S7[getUnsignedInt(x[1])] ^ S8[getUnsignedInt(x[3])] ^ S8[getUnsignedInt(z[2])];
        unscramble(x4x5x6x7I, x, 4, 8);
        x8x9xAxBI = z4z5z6z7 ^ S5[getUnsignedInt(x[7])] ^ S6[getUnsignedInt(x[6])] ^ S7[getUnsignedInt(x[5])] ^ S8[getUnsignedInt(x[4])] ^ S5[getUnsignedInt(z[1])];
        unscramble(x8x9xAxBI, x, 8, 12);
        xCxDxExFI = zCzDzEzF ^ S5[getUnsignedInt(x[10])] ^ S6[getUnsignedInt(x[9])] ^ S7[getUnsignedInt(x[11])] ^ S8[getUnsignedInt(x[8])] ^ S6[getUnsignedInt(z[3])];
        unscramble(xCxDxExFI, x, 12, 16);

        key.setK(20, S5[getUnsignedInt(x[3])] ^ S6[getUnsignedInt(x[2])] ^ S7[getUnsignedInt(x[12])] ^ S8[getUnsignedInt(x[13])] ^ S5[getUnsignedInt(x[8])]);
        key.setK(21, S5[getUnsignedInt(x[1])] ^ S6[getUnsignedInt(x[0])] ^ S7[getUnsignedInt(x[14])] ^ S8[getUnsignedInt(x[15])] ^ S6[getUnsignedInt(x[13])]);
        key.setK(22, S5[getUnsignedInt(x[7])] ^ S6[getUnsignedInt(x[6])] ^ S7[getUnsignedInt(x[8])] ^ S8[getUnsignedInt(x[9])] ^ S7[getUnsignedInt(x[3])]);
        key.setK(23, S5[getUnsignedInt(x[5])] ^ S6[getUnsignedInt(x[4])] ^ S7[getUnsignedInt(x[10])] ^ S8[getUnsignedInt(x[11])] ^ S8[getUnsignedInt(x[7])]);

        z0z1z2z3 = x0x1x2x3I ^ S5[getUnsignedInt(x[13])] ^ S6[getUnsignedInt(x[15])] ^ S7[getUnsignedInt(x[12])] ^ S8[getUnsignedInt(x[14])] ^ S7[getUnsignedInt(x[8])];
        unscramble(z0z1z2z3, z, 0, 4);
        z4z5z6z7 = x8x9xAxBI ^ S5[getUnsignedInt(z[0])] ^ S6[getUnsignedInt(z[2])] ^ S7[getUnsignedInt(z[1])] ^ S8[getUnsignedInt(z[3])] ^ S8[getUnsignedInt(x[10])];
        unscramble(z4z5z6z7, z, 4, 8);
        z8z9zAzB = xCxDxExFI ^ S5[getUnsignedInt(z[7])] ^ S6[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[5])] ^ S8[getUnsignedInt(z[4])] ^ S5[getUnsignedInt(x[9])];
        unscramble(z8z9zAzB, z, 8, 12);
        zCzDzEzF = x4x5x6x7I ^ S5[getUnsignedInt(z[10])] ^ S6[getUnsignedInt(z[9])] ^ S7[getUnsignedInt(z[11])] ^ S8[getUnsignedInt(z[8])] ^ S6[getUnsignedInt(x[11])];
        unscramble(zCzDzEzF, z, 12, 16);

        key.setK(24, S5[getUnsignedInt(z[3])] ^ S6[getUnsignedInt(z[2])] ^ S7[getUnsignedInt(z[12])] ^ S8[getUnsignedInt(z[13])] ^ S5[getUnsignedInt(z[9])]);
        key.setK(25, S5[getUnsignedInt(z[1])] ^ S6[getUnsignedInt(z[0])] ^ S7[getUnsignedInt(z[14])] ^ S8[getUnsignedInt(z[15])] ^ S6[getUnsignedInt(z[12])]);
        key.setK(26, S5[getUnsignedInt(z[7])] ^ S6[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[8])] ^ S8[getUnsignedInt(z[9])] ^ S7[getUnsignedInt(z[2])]);
        key.setK(27, S5[getUnsignedInt(z[5])] ^ S6[getUnsignedInt(z[4])] ^ S7[getUnsignedInt(z[10])] ^ S8[getUnsignedInt(z[11])] ^ S8[getUnsignedInt(z[6])]);

        x0x1x2x3I = z8z9zAzB ^ S5[getUnsignedInt(z[5])] ^ S6[getUnsignedInt(z[7])] ^ S7[getUnsignedInt(z[4])] ^ S8[getUnsignedInt(z[6])] ^ S7[getUnsignedInt(z[2])];
        unscramble(x0x1x2x3I, x, 0, 4);
        x4x5x6x7I = z0z1z2z3 ^ S5[getUnsignedInt(x[15])] ^ S6[getUnsignedInt(x[15])] ^ S7[getUnsignedInt(x[15])] ^ S8[getUnsignedInt(x[15])] ^ S8[getUnsignedInt(z[2])];
        unscramble(x4x5x6x7I, x, 4, 8);
        x8x9xAxBI = x4x5x6x7I ^ S5[getUnsignedInt(x[7])] ^ S6[getUnsignedInt(x[6])] ^ S7[getUnsignedInt(x[5])] ^ S8[getUnsignedInt(x[4])] ^ S5[getUnsignedInt(z[1])];
        unscramble(x8x9xAxBI, x, 8, 12);
        xCxDxExFI = zCzDzEzF ^ S5[getUnsignedInt(x[10])] ^ S6[getUnsignedInt(x[9])] ^ S7[getUnsignedInt(x[11])] ^ S8[getUnsignedInt(x[8])] ^ S6[getUnsignedInt(z[3])];
        unscramble(xCxDxExFI, x, 12, 16);

        key.setK(28, S5[getUnsignedInt(x[8])] ^ S6[getUnsignedInt(x[10])] ^ S7[getUnsignedInt(x[7])] ^ S8[getUnsignedInt(x[6])] ^ S5[getUnsignedInt(x[3])]);
        key.setK(29, S5[getUnsignedInt(x[10])] ^ S6[getUnsignedInt(x[11])] ^ S7[getUnsignedInt(x[5])] ^ S8[getUnsignedInt(x[4])] ^ S6[getUnsignedInt(x[7])]);
        key.setK(30, S5[getUnsignedInt(x[12])] ^ S6[getUnsignedInt(x[13])] ^ S7[getUnsignedInt(x[3])] ^ S8[getUnsignedInt(x[2])] ^ S7[getUnsignedInt(x[8])]);
        key.setK(31,  S5[getUnsignedInt(x[14])] ^ S6[getUnsignedInt(x[15])] ^ S7[getUnsignedInt(x[1])] ^ S8[getUnsignedInt(x[0])] ^ S8[getUnsignedInt(x[13])]);

        key.keysPairs();

//        System.out.println("[ LOG ] Generating Kr,Km");
//        System.out.print("|--");
//
//        for(int i = 0; i<100 ; i++) {
//            try {
//                System.out.print("-");
//                Thread.sleep(10);
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }
//        System.out.print("|\n");
//
//        for(int i = 0 ; i<16; i++){
//            System.out.print("[" + i + "] Kr" + key.getKr(i)+"\t\t");
//            System.out.print("Km["+i+"]" + key.getKm(i));
//            System.out.println();
//        }
        /*The end of the key generation!!!!!*/
    }

    public static int getUnsignedInt(byte data)
    {
        return (int)( Byte.toUnsignedLong(data) & 0xFFFFFFFFL);
    }

    private void unscramble(int x, byte[] array, int start, int stop) {
        byte[] tmp = ByteBuffer.allocate(4).putInt(x).array();
        for (int i = start, j = 0; i < stop; i++, j++)
            array[i] = (byte) (tmp[j] & 0xFF);
    }

    private final int f1(int I, int m, int r){
        I = m + I;
        I = I << r | I >>> (32 - r);
        return (((S1[(I >>> 24) & 0xFF])
                ^ S2[(I >>> 16) & 0xFF])
                - S3[(I >>>  8) & 0xFF])
                + S4[ I         & 0xFF];
    }

    private final int f2(int I, int m, int r){
        I = m ^ I;
        I = I << r | I >>> (32 - r);
        return (((S1[(I >>> 24) & 0xFF])
                - S2[(I >>> 16) & 0xFF])
                + S3[(I >>>  8) & 0xFF])
                ^ S4[ I         & 0xFF];
    }

    private final int f3(int I, int m, int r){
        I = m - I;
        I = I << r | I >>> (32 - r);
        return (((S1[(I >>> 24) & 0xFF])
                + S2[(I >>> 16) & 0xFF])
                ^ S3[(I >>>  8) & 0xFF])
                - S4[ I         & 0xFF];
    }


    /* DECRYPTION PART!*/


    public String decrypt(ArrayList<Byte> encryptedData){

        int n;
        byte[] data= new byte[8];
        byte[] copydata= new byte[8];
        StringBuilder sb = new StringBuilder();

        for(int j=0;j<encryptedData.size();j++)
        {
            data[j%8]=encryptedData.get(j);
            if((j+1)%8==0)
            {
                System.arraycopy(data, 0, copydata, 0, data.length);
                plaintext = decryptLogic(copydata);
                sb.append(new String(plaintext));
            }
        }
        int padding = plaintext[7];
        int len = sb.length();
        return sb.toString().substring(0,len-padding);
    }

    public String decrypt(String datum){

        byte[] cipher = datum.getBytes();
        byte[] data= new byte[8];
        byte[] copydata= new byte[8];
        StringBuilder sb = new StringBuilder();
        ArrayList<Byte> enc = new ArrayList<>();

        for(int i = 0; i < cipher.length; i++)
            enc.add(cipher[i]);

        for(int j=0;j<enc.size();j++)
        {
            data[j%8]=enc.get(j);
            if((j+1)%8==0)
            {
                System.arraycopy(data, 0, copydata, 0, data.length);
                plaintext = decryptLogic(copydata);
                sb.append(new String(plaintext));
            }
        }
        int padding = plaintext[7];
        int len = sb.length();
        return sb.toString().substring(0,len-padding);
    }

    private byte[] decryptLogic(byte[] data){

        byte[] result = new byte[8];

        int L = ByteBuffer.wrap(data, 0, 4).getInt();
        int R = ByteBuffer.wrap(data, 4, 4).getInt();
        /*  in the decrypion part the keys are opposite*/
        L ^= f1(R, key.getKm(15), key.getKr(15));//round 1 in decryption
        R ^= f3(L, key.getKm(14), key.getKr(14));
        L ^= f2(R, key.getKm(13), key.getKr(13));
        R ^= f1(L, key.getKm(12), key.getKr(12));
        L ^= f3(R, key.getKm(11), key.getKr(11));
        R ^= f2(L, key.getKm(10), key.getKr(10));
        L ^= f1(R, key.getKm(9), key.getKr(9));
        R ^= f3(L, key.getKm(8), key.getKr(8));
        L ^= f2(R, key.getKm(7), key.getKr(7));
        R ^= f1(L, key.getKm(6), key.getKr(6));
        L ^= f3(R, key.getKm(5), key.getKr(5));
        R ^= f2(L, key.getKm(4), key.getKr(4));
        L ^= f1(R, key.getKm(3), key.getKr(3));
        R ^= f3(L, key.getKm(2), key.getKr(2));
        L ^= f2(R, key.getKm(1), key.getKr(1));
        R ^= f1(L, key.getKm(0), key.getKr(0));//round 16


        unscramble(R, result, 0, 4);
        unscramble(L, result, 4, 8);

        return result;
    }

    public String KeyGenerator() throws NoSuchAlgorithmException {
        return this.encryptionKey;
    }

    public void save() throws NoSuchAlgorithmException {
        String secretKey = KeyGenerator();
        try {
            FileWriter fw = new FileWriter("secret_key.pk");
            fw.write(secretKey);
            fw.close();
        } catch (Exception ignored) {}
    }


}