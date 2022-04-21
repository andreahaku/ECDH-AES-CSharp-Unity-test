using System;
using System.Linq;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;


public class SDK_ECDH : MonoBehaviour
{
    // ECDH related constants
    private static string Algorithm = "ECDH";
    private static X9ECParameters curve = ECNamedCurveTable.GetByName("secp256k1");
    private static ECDomainParameters domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

    // AES related constants
    private static readonly SecureRandom Random = new SecureRandom();
    public static readonly int NonceByteSize = 16;

    // returns initialisation vector (byte array)
    public static byte[] NewIv()
    {
        var iv = new byte[NonceByteSize];
        Random.NextBytes(iv);
        return iv;
    }

    // converts hex string into byte array
    public static Byte[] HexToByte(string hexStr)
    {
        byte[] bArray = new byte[hexStr.Length / 2];

        for (int i = 0; i < (hexStr.Length / 2); i++)
        {
            byte firstNibble = Byte.Parse(hexStr.Substring((2 * i), 1), 
                                System.Globalization.NumberStyles.HexNumber); // [x,y)
            byte secondNibble = Byte.Parse(hexStr.Substring((2 * i) + 1, 1), 
                                System.Globalization.NumberStyles.HexNumber);
            int finalByte = (secondNibble) | (firstNibble << 4);    // bit-operations 
                                                                    // only with numbers, not bytes.
            bArray[i] = (byte)finalByte;
        }
        
        return bArray;
    }

    // converts byte data into hex string
    public static string toHex(byte[] data)
    {
        string hex = string.Empty;
        
        foreach (byte c in data)
        {
            hex += c.ToString("X2");
        }
        
        return hex;
    }

    // converts string data into hex string
    public static string toHex(string asciiString)
    {
        string hex = string.Empty;
        
        foreach (char c in asciiString)
        {
            int tmp = c;
            hex += string.Format("{0:x2}", System.Convert.ToUInt32(tmp.ToString()));
        }
        
        return hex;
    }

    // generates and return the ecdh asymmetric keypair
    public static AsymmetricCipherKeyPair generateECDH()
    {
        var secureRandom = new SecureRandom();
        var keyParams = new ECKeyGenerationParameters(domain, secureRandom);

        var generator = new ECKeyPairGenerator(Algorithm);
        generator.Init(keyParams);
        var keyPair = generator.GenerateKeyPair();

        return keyPair;
    }

    // returns public key in base64 from keypair
    public static string getPublicKey(AsymmetricCipherKeyPair keyPair){
        var publicKey = keyPair.Public as ECPublicKeyParameters;
        string b64PublicKey = Convert.ToBase64String(publicKey.Q.GetEncoded());

        return b64PublicKey;
    }

    // computes asymmetric shared key from local keypair and remote public key(base64)
    public static BigInteger computeECDHSecret(AsymmetricCipherKeyPair keyPair, string otherPublicKey){
        byte[] publicKey = Convert.FromBase64String (otherPublicKey);

        var remotePublicKey = new ECPublicKeyParameters(domain.Curve.DecodePoint(publicKey), domain);

        IBasicAgreement keyAgree = AgreementUtilities.GetBasicAgreement (Algorithm);
        keyAgree.Init (keyPair.Private);
        BigInteger sharedKey = keyAgree.CalculateAgreement(remotePublicKey);

        return sharedKey;
    }

    // encrypts message using key (byte format) and returns base64 encrypted string
    public static string encryptAuthIV(string PlainText, byte[] key)
    {
        string sR = string.Empty;
        
        try
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(PlainText);
            byte[] iv = NewIv();

            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);

            cipher.Init(true, parameters);

            byte[] encryptedBytes = new byte[cipher.GetOutputSize(plainBytes.Length)];
            Int32 retLen = cipher.ProcessBytes(plainBytes, 0, plainBytes.Length, encryptedBytes, 0);
            cipher.DoFinal(encryptedBytes, retLen);

            byte[] completeMessage = iv.Concat(encryptedBytes).ToArray();

            sR = Convert.ToBase64String(completeMessage, Base64FormattingOptions.None);
        }
        catch (Exception ex)
        {
            Debug.Log(ex.Message);
            Debug.Log(ex.StackTrace);
        }

        return sR;
    }

    // decrypts base64 message using key (byte format) and returns plain test message
    public static string decryptAuthIV(string EncryptedText, byte[] key)
    {
        string sR = string.Empty;
        
        try
        {
            var iv = new byte[NonceByteSize];
            byte[] encryptedBytes = Convert.FromBase64String(EncryptedText);
            Array.Copy (encryptedBytes, iv, NonceByteSize);
            
            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);
            // ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);

            cipher.Init(false, parameters);
            int arrayLength = encryptedBytes.Length - NonceByteSize;
            byte[] plainBytes = new byte[arrayLength];
            Array.Copy (encryptedBytes, NonceByteSize, plainBytes, 0, arrayLength);

            Int32 retLen = cipher.ProcessBytes(plainBytes, 0, plainBytes.Length, plainBytes, 0);
            cipher.DoFinal(plainBytes, retLen);

            sR = Encoding.UTF8.GetString(plainBytes).Substring(0,plainBytes.Length-16).TrimEnd("\r\n\0".ToCharArray());
        }
        catch (Exception ex)
        {
            Debug.Log(ex.Message);
            Debug.Log(ex.StackTrace);
        }

        return sR;
    }

    void Start()
    {
        // generate ECDH keys
        AsymmetricCipherKeyPair aliceKeyPair = generateECDH ();
        AsymmetricCipherKeyPair bobKeyPair = generateECDH ();

        // get public key
        string alicePublicKey = getPublicKey(aliceKeyPair);
        string bobPublicKey = getPublicKey(bobKeyPair);

        // calculate shared key using local keys and remote public key
        BigInteger aliceAgree = computeECDHSecret (aliceKeyPair, bobPublicKey);
        BigInteger bobAgree = computeECDHSecret (bobKeyPair, alicePublicKey);

        // messages to be exchanged
        string message = "This is a test message!";
        string message2 = "This is another test message!!";

        // encrypts first message from Alice and Bob decrypts it
        string aliceEncryptedText = encryptAuthIV(message, aliceAgree.ToByteArrayUnsigned ());
        string bobDecryptedText = decryptAuthIV(aliceEncryptedText, bobAgree.ToByteArrayUnsigned ());

        // encrypts first message from Bob and Alice decrypts it
        string bobEncryptedText = encryptAuthIV(message2, bobAgree.ToByteArrayUnsigned ());
        string aliceDecryptedText = decryptAuthIV(bobEncryptedText, aliceAgree.ToByteArrayUnsigned ());
    }

    void Update()
    {
        
    }
}
