using System;
using System.Diagnostics;
using System.Numerics;
using System.Threading;
using System.Security.Cryptography;
using System.IO;
using System.Text;
namespace NPK2018
{
    static class Program
    {
        // Useless function
        public static void Main()
        {
            CurvePoint G = new CurvePoint(); //special point on elliptic curve
            G.mod = BigInteger.Parse("6277101735386680763835789423207666416083908700390324961279"); //parameter (used in both keys)
            G.a = -3; //parameter (used in both keys) describes curve
            G.b = BigInteger.Parse("2455155546008943817740293915197451784769108058161191238065"); //parameter (used in both keys) describes curve
            G.x = BigInteger.Parse("602046282375688656758213480587526111916698976636884684818"); //parameter (used in both keys) describes point position
            G.y = BigInteger.Parse("174050332293622031404857552280219410364023488927386650641"); //parameter (used in both keys) describes point position
            BigInteger n = BigInteger.Parse("6277101735386680763835789423176059013767194773182842284081"); //parameter (used in both keys)

            BigInteger d = BigInteger.Parse("793986734895809328509738052968530949689428096295830986985"); // d is a private key. it is okay if d is not very big
            CurvePoint Q = d * G; // Q is part of the open key

            HashAlgorithm h = SHA512.Create();
            BigInteger msg = new BigInteger(h.ComputeHash(Encoding.UTF8.GetBytes(Console.ReadLine())));
            var signature = CurvePoint.GetSignature(msg, d, G, n);
            Console.WriteLine(signature);
            Console.WriteLine(CurvePoint.VerifySignature(msg, signature, G, Q, n)); //Shows that signature is okay
            /*
            StreamReader sr = new StreamReader("RSA Primes/2048b0.txt"); //Change to use other primes to generate keys
            BigInteger p = BigInteger.Parse(sr.ReadLine());
            sr.Close();
            sr = new StreamReader("RSA Primes/2048b1.txt"); //Change to use other primes to generate keys
            BigInteger q = BigInteger.Parse(sr.ReadLine());
            sr.Close();
            // We can use RSA.GetRandomPrime(int length) with our own length (in bytes), but test shows, that this function works at O(n^3), so you'll wait too long if you will try to generate primes greater, then 1024bit (128 bytes) length.
            var keys = RSA.GetRSAKeyPair(p, q);
            var public_key = keys.Item1;    // public_key must be tranfered and private_key must be kept private
            var private_key  = keys.Item2;  // but as it is just to test everything i dont mind keeping them all here

            string msg = Console.ReadLine();
            string signature = Convert.ToBase64String(RSA.GetSignature(Encoding.UTF8.GetBytes(msg), private_key)); //Function returns byte[], but to see what is happening i encoded it using base64 
            Console.WriteLine(signature); 
            byte[] ver_bytes = RSA.VerifySignature(Convert.FromBase64String(signature), public_key); //Functions GetSignature and VerifySignature are different, because block sizes differs and we need padding for the last block when signing  and then delete this padding when verifying
            string rebuilded = Encoding.UTF8.GetString(ver_bytes).Trim((char)0);
            Console.WriteLine(rebuilded); //This output is just to show that everything works
            //P.S. GetSignature can works really slow when pig primes are picked
            */
        }
        //Usefull function
        public static BigInteger ModInvert(this BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
    }
}