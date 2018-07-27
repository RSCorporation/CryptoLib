using System;
using System.Numerics;
namespace NPK2018
{
    public class CurvePoint
    {
        public BigInteger a;
        public BigInteger b;
        public BigInteger x;
        public BigInteger y;
        public BigInteger mod;
        public CurvePoint(CurvePoint p)
        {
            x = p.x;
            y = p.y;
            a = p.a;
            b = p.b;
            mod = p.mod;
        }
        public CurvePoint()
        {
            x = BigInteger.Zero;
            y = BigInteger.Zero;
            a = BigInteger.Zero;
            b = BigInteger.Zero;
            mod = BigInteger.Zero;
        }
        public static CurvePoint operator +(CurvePoint p1, CurvePoint p2)
        {
            CurvePoint res = new CurvePoint();
            res.a = p1.a;
            res.b = p1.b;
            res.mod = p1.mod;
            BigInteger dy = p2.y - p1.y;
            BigInteger dx = p2.x - p1.x;
            if (dx < 0) dx += p1.mod;
            if (dy < 0) dy += p1.mod;
            BigInteger alpha = (dy * dx.ModInvert(p1.mod)) % p1.mod;
            if (alpha < 0) alpha += p1.mod;
            res.x = (alpha * alpha - p1.x - p2.x) % p1.mod;
            if (res.x < 0) res.x += p1.mod;
            res.y = (alpha * (p1.x - res.x) - p1.y) % p1.mod;
            if (res.y < 0) res.y += p1.mod;
            return res;
        }
        public static CurvePoint Double(CurvePoint P)
        {
            CurvePoint p2 = new CurvePoint();
            p2.a = P.a;
            p2.b = P.b;
            p2.mod = P.mod;
            BigInteger dx = 2 * P.y;
            if (dx < 0) dx += P.mod;
            BigInteger dy = 3 * P.x * P.x + P.a;
            if (dy < 0) dy += P.mod;
            BigInteger alpha = (dy * dx.ModInvert(P.mod)) % P.mod;
            p2.x = (alpha * alpha - P.x - P.x) % P.mod;
            p2.y = ((P.x - p2.x) * alpha - P.y) % P.mod;
            if (p2.x < 0) p2.x += P.mod;
            if (p2.y < 0) p2.y += P.mod;
            return p2;
        }
        public static CurvePoint operator *(BigInteger x, CurvePoint p)
        {
            CurvePoint temp = p;
            x--;
            while (x != 0)
            {
                if ((x % 2) != 0)
                {
                    if ((temp.x == p.x) || (temp.y == p.y)) temp = Double(temp);
                    else temp = temp + p;
                    x--;
                }
                x /= 2;
                p = Double(p);
            }
            return temp;
        }
        public static Tuple<BigInteger, BigInteger> GetSignature(BigInteger msg, BigInteger d, CurvePoint G, BigInteger n)
        {
            BigInteger e = msg % n;
            if (e < 0) e = -e;
            if (e == 0) e = 1;
            CurvePoint C = new CurvePoint();
            BigInteger r = BigInteger.Zero;
            BigInteger s = BigInteger.Zero;
            int length = n.ToByteArray().Length;
            BigInteger k = BigInteger.Zero;
            do
            {
                do
                {
                    k = RSA.GetRandomBigInteger(length-1);
                } while ((k < 0) || (k > n));
                C = k * G;
                r = C.x % n;
                s = ((r * d) + (k * e)) % n;
            } while ((r == 0)||(s==0));
            return Tuple.Create(r,s);
        }
        public static bool VerifySignature(BigInteger msg, Tuple<BigInteger, BigInteger> signature, CurvePoint G, CurvePoint Q, BigInteger n)
        {
            BigInteger r = signature.Item1;
            BigInteger s = signature.Item2;
            if ((r < 1) || (r > (n - 1)) || (s < 1) || (s > (n - 1))) return false;
            BigInteger e = msg % n;
            if (e < 0) e = -e;
            if (e == 0) e = 1;
            BigInteger v = e.ModInvert(n);
            BigInteger param1 = (s * v) % n;
            BigInteger param2 = n + ((-(r * v)) % n);
            CurvePoint A = param1 * G;
            CurvePoint B = param2 * Q;
            CurvePoint C = A + B;
            BigInteger R = C.x % n;
            return R == r;
        }
    }
}