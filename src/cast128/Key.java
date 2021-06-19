package cast128;

public class Key{

    private int[] K = new int[32];
    private int[] Km = new int[16];
    private int[] Kr = new int[16];

    public void setK(int index, int value){
        K[index] = value;
    }

    public void keysPairs(){
        for (int i = 0; i < 16; i++) {
            Km[i] = K[i];
            Kr[i] = K[16 + i] & 0x1F;
        }
    }

    public int getKm(int index){
        return Km[index];
    }

    public int getKr(int index){
        return Kr[index];
    }
}