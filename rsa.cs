using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
namespace NPK2018
{
    class RSA
    {
        static RandomNumberGenerator random = RandomNumberGenerator.Create(); //For personal needs
        public static bool IsPrime(BigInteger candidate, int numoftests = 64) //Miller-Rabin
        {
            if(candidate==2||candidate==3) return true;
            if(candidate<=1||candidate%2==0) return false;
            int s = 0;
            BigInteger r = candidate - 1;
            while(r%2==0)
            {
                s++;
                r/=2;
                for(int ijk = 0; ijk < numoftests; ijk++)
                {
                    BigInteger a = (GetRandomBigInteger(64)%(candidate-3)+candidate-3)%(candidate-3)+2;
                    BigInteger x = BigInteger.ModPow(a, r, candidate);
                    if(x!=1 && x!=(candidate-1))
                    {
                        for(int j = 0; j < s && x!=(candidate - 1); j++)
                        {
                            x = (x * x) % candidate;
                            if(x == 1) return false;
                        }
                        if(x != (candidate - 1)) return false;
                    }
                }
            }
            return true;
        }
        public static BigInteger GetRandomPrime(int bytelength)
        {
            BigInteger candidate;
            do
            {
                candidate = GetRandomBigInteger(bytelength);
                if(candidate % 2 == 0) candidate++;
            } while (!IsPrime(candidate, bytelength));
            return candidate;
        }
        public static BigInteger GetRandomBigInteger(int bytelength)
        {
            byte[] bytes = new byte[bytelength];
            random.GetBytes(bytes);
            bytes [bytes.Length - 1] &= (byte)0x7F;
            return new BigInteger(bytes);
        }
        public static Tuple<Tuple<BigInteger, BigInteger>, Tuple<BigInteger, BigInteger>> GetRSAKeyPair()
        {
            return GetRSAKeyPair(GetRandomPrime(128), GetRandomPrime(128));
        }
        public static Tuple<Tuple<BigInteger, BigInteger>, Tuple<BigInteger, BigInteger>> GetRSAKeyPair(BigInteger p, BigInteger q)
        {
            BigInteger n = p * q;
            BigInteger phin = (p-1)*(q-1);
            BigInteger e = 65537;
            BigInteger d = e.ModInvert(phin);
            if((e*d)%phin!=1) throw new Exception("What the ****?");
            return Tuple.Create(Tuple.Create(e, n), Tuple.Create(d, n));
        }
        public static BigInteger EncDec(BigInteger msg, Tuple<BigInteger, BigInteger> key) //Encrypts/decrypts messages
        {
            if(key.Item1 == 65537)
            {
                BigInteger curr = msg;
                for(int ijk = 0; ijk < 16; ijk++) curr = (curr * curr) % key.Item2;
                return (curr * msg) % key.Item2;
            }
            return BigInteger.ModPow(msg, key.Item1, key.Item2);
        }
        static byte[] GetOrVerifySignature(byte[] bytes, Tuple<BigInteger, BigInteger> key, bool verify_mode)
        {
            int targetlength = verify_mode ? key.Item2.ToByteArray().Length - 1 : key.Item2.ToByteArray().Length;
            int initlength = !verify_mode ? key.Item2.ToByteArray().Length - 1 : key.Item2.ToByteArray().Length;
            byte[] signature = new byte[(bytes.Length+targetlength)/(targetlength)*(targetlength) - (verify_mode ? targetlength : 0)];
            
            for(int i = 0; i < bytes.Length; i+=initlength)
            {
                int bytecnt = bytes.Length - i >= initlength ? initlength : bytes.Length - i;
                byte[] blockbytes = new byte[bytecnt];
                Array.Copy(bytes, i, blockbytes, 0, bytecnt);
                BigInteger block = new BigInteger(blockbytes);
                BigInteger block_enc = RSA.EncDec(block, key);
                var enc =  block_enc.ToByteArray();
                Array.Copy(enc, 0, signature, i/initlength*targetlength, (targetlength > enc.Length) ? enc.Length : targetlength);
            }
            return signature;
        }
        public static byte[] GetSignature(byte[] bytes, Tuple<BigInteger, BigInteger> key)
        {
            return GetOrVerifySignature(bytes, key, false);
        }
        public static byte[] VerifySignature(byte[] bytes, Tuple<BigInteger, BigInteger> key)
        {
            return GetOrVerifySignature(bytes, key, true);
        }
    }
}