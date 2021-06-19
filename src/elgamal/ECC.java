package elgamal;

import java.math.BigInteger;

public class ECC {
    public static double EPS = 1e-5;
    // ECC equation: y^2 = x^3 + a*x + b mod p
    public static BigInteger a, b, p;
    // base Point
    public static Point basePoint;

    public static void setParam(BigInteger a, BigInteger b, BigInteger p, Point basePoint){
        ECC.a = a;
        ECC.b = b;
        ECC.p = p;
        ECC.basePoint = basePoint;
    }

    public static Point add(Point p, Point q){
        Point result = new Point();

        if(p.x.compareTo(q.x) == 0 && p.y.compareTo(q.y) == 0){
            return ECC.doubles(p);
        }

        if(p.isInfinite && q.isInfinite){
            Point inf = new Point(BigInteger.ZERO, BigInteger.ZERO);
            inf.isInfinite = true;
            return inf;
        } else if(p.isInfinite){
            return q;
        } else if(q.isInfinite){
            return p;
        }

        if(p.x.compareTo(q.x) == 0){ // point in infinity
            Point inf = new Point(BigInteger.ZERO, BigInteger.ZERO);
            inf.isInfinite = true;
            return inf;
        }

        BigInteger gradient = q.y.subtract(p.y).multiply( q.x.subtract(p.x).mod(ECC.p).modInverse(ECC.p)).mod(ECC.p);

        result.x = gradient.multiply(gradient).subtract(p.x).subtract(q.x).mod(ECC.p);
        result.y = gradient.multiply(p.x.subtract(result.x)).subtract(p.y).add(ECC.p).mod(ECC.p);

        return result;
    }

    public static Point minus(Point p, Point q) {
        Point qMinus = new Point(q.x,  q.y.multiply(new BigInteger("-1")).mod(ECC.p));
        return ECC.add(p, qMinus);
    }

    public static Point doubles(Point a){
        BigInteger gradient = a.x.multiply(a.x).multiply(new BigInteger("3")).add(ECC.a).multiply(new BigInteger("2").multiply(a.y).modInverse(ECC.p)).mod(ECC.p);
        Point result = new Point();

        result.x = gradient.multiply(gradient).subtract(new BigInteger("2").multiply(a.x)).mod(ECC.p);
        result.y = gradient.multiply(a.x.subtract(result.x)).subtract(a.y).mod(ECC.p);

        return result;
    }

    public static Point times(BigInteger a, Point b){
        if(a.equals(BigInteger.ZERO))
            return new Point(BigInteger.ZERO, BigInteger.ZERO);
        else if(a.equals(BigInteger.ONE)){
            return b;
        } else if(a.mod(new BigInteger("2")).equals(BigInteger.ZERO)){
            return ECC.times(a.divide(new BigInteger("2")), ECC.doubles(b));
        } else {
            return ECC.add(ECC.times(a.subtract(BigInteger.ONE), b), b);
        }
    }

    public static BigInteger solveY(BigInteger x) {

        BigInteger y = SquareRootModular.sqrtP(x.multiply(x).multiply(x).add(ECC.a.multiply(x)).add(ECC.b).mod(ECC.p), ECC.p);
        if (y==null) {
            return new BigInteger("-1");
        }
        else {
            return y;
        }
    }

    public static BigInteger k = new BigInteger("30");

    public static Point messageToPoint(BigInteger m) {
        BigInteger x,y;
        BigInteger mk = m.multiply(k);
        for (BigInteger i = BigInteger.ONE;
             i.compareTo(k) < 0;
             i = i.add(BigInteger.ONE)) {
            x = mk.add(i);
            y = ECC.solveY(x);
            if (!y.equals(new BigInteger("-1"))) {
                return new Point (x,y);
            }
        }
        return new Point(new BigInteger("-1"), new BigInteger("-1"));
    }

    public static BigInteger pointToMessage(Point p) {
        return p.x.subtract(BigInteger.ONE).divide(new BigInteger(String.valueOf(k)));
    }

}