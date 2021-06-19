package cast128;

import java.util.ArrayList;

public class Utils {
    private static String digits = "0123456789abcdef";

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data   the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static byte[] toArray(ArrayList<Byte> bytes) {
        byte[] t = new byte[bytes.size()];
        for(int i = 0; i < bytes.size(); i++)
            t[i] = bytes.get(i);

        return t;
    }

    public static String bytesToHex(ArrayList<Byte> bytes) {
        return Utils.toHex(Utils.toArray(bytes));
    }
}