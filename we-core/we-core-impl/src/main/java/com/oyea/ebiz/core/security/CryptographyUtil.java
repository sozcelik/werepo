package com.brightpoint.directconnect.core.security;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAMultiPrimePrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.shiro.codec.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author vladimirp
 */
public final class CryptographyUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptographyUtil.class);
    private static Map<String, SecretKey> aesKeyMap = new ConcurrentHashMap<String, SecretKey>();
    private static final Charset PLAIN_TEXT_ENCODING = Charset.forName("UTF-8");
    private static final String CIPHER_TRANSFORMATION = "AES/CTR/NoPadding";
    private static final Integer BYTE = 8;
    private static final Integer DOUBLE_BYTE = 16;

    private static Cipher rsaCipher;

    private static RSAPublicKey rsaPublicKey;
    private static RSAPrivateKey rsaPrivateKey;
    
    private static RSAPublicKeySpec spec;

    private static final String[] KEYHEX = {
                    "510c151a949a4962a7c35d02e552643f" // modulus n
                                    + "a23ce6c582fc8b220259f42710f3bf97"
                                    + "8c0be610bc83086da1607a900c214347"
                                    + "39ebbe1570fadc1dce14c00cdab7ff77"
                                    + "20226b49905c4a3a5065d4c644a57802"
                                    + "4b810a3e7d6d02ac8fa3ea80824e6d07"
                                    + "c3a4b11614f36c190991689d4a9264bc"
                                    + "8502d6e5fc4c00713755a028e1ed2ff7",
                    "3", // public exponent e
                    "36080e11b866db971a823e01ee36ed7f" // private exponent d
                                    + "c17def2e5753076c01914d6f60a27fba"
                                    + "5d5d440b28575af3c0eafc6008162cda"
                                    + "269d2963a0a73d69340dd55de72554f9"
                                    + "54a9d4655202e94115d23ccd8d3ff1aa"
                                    + "6c8ed6fc7e141b2b48c92de3a94f9bdb"
                                    + "d3c50f547ad434f17840ef009aa48551"
                                    + "ddc98d47ec155114c40d10dd11ba5bab",
                    "9ce939672e65b4293d7b6ae8c2e1a544" // secret prime factor p
                                    + "f73ed640a9fe1f7c60f91a76ceb7354b"
                                    + "2c2bfb070d650243a4c99e0a59fccb28"
                                    + "ad79bc62487ebcec135a429b659a9a41",
                    "843a734a66f2382f722f0ea92de3e83d" // secret prime factor q
                                    + "b16bf1831650ba6f417d0b34359fcdf2"
                                    + "d9d11f104f501a6b30666412089ed199"
                                    + "0adac697d1ad49e5fde7c441e1bb0c37",
                    "689b7b9a1eee781b7e524745d74118d8" // d mod (p-1)
                                    + "a4d48ed5c6a96a52eb50bc4f347a2387"
                                    + "72c7fcaf5e4356d7c3311406e6a88770"
                                    + "73a67d96daff289d623c2c679911bc2b",
                    "5826f786ef4c2574f6ca09c61e97f029" // d mod (q-1)
                                    + "20f2a1020ee07c4a2ba8b222ce6a894c"
                                    + "913614b58a3566f2204442b6b069e110"
                                    + "b1e72f0fe11e3143fe9a82d6967cb2cf",
                    "4e1ffca46ce5dc84bedaa36c9c91988f" // q^-1 mod p
                                    + "5a78af49befefdc0c7ec91062a2b42c5"
                                    + "b65c10f85ca6c0e4d78158e789099ee9"
                                    + "e5cb3a8dd9c5d0297fa35a5ab1debd33"
    };

    private CryptographyUtil() {
        ;
    }

    /**
     * @return Hexadecimal representation of RSA public key
     */
    public static byte[] getRSAPublicKey() {
        init();
        return rsaPublicKey.getEncoded();
    }

    /**
     * @return Hexadecimal representation of RSA public modulus
     */
    public static byte[] getRSAPublicModulus() {
        init();
        return spec.getModulus().toByteArray();
    }
    
    /**
     * @return Hexadecimal representation of RSA public exponent
     */
    public static byte[] getRSAPublicExponent() {
        init();
        return spec.getPublicExponent().toByteArray();
    }
    
    /**
     * @return String representation of RSA public key as public exponent and
     *         modulus
     */
    public static String getRSAPublicKeyAsString() {
        init();
        StringBuffer retVal = new StringBuffer();

        retVal.append(KEYHEX[0]);
        retVal.append("|");
        retVal.append(KEYHEX[1]);
        return retVal.toString();
    }

    /**
     * @param message
     *            A message as a byte array that will be encrypted with class
     *            defined RSA public key
     * @return Hexadecimal representation of encrypted message
     */
    public synchronized static byte[] encryptRSAString(final byte[] message) {
        byte[] retVal = null;
        init();
        try {
            rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            retVal = rsaCipher.doFinal(message);

        } catch (InvalidKeyException e) {
            LOGGER.error("Invalid RSA public key specified", e);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("Invalid RSA key block specified", e);
        } catch (BadPaddingException e) {
            LOGGER.error("Bad RSA key padding specified", e);
        }
        return retVal;
    }

    /**
     * @param message
     *            A message as a byte array
     * @param publicKey
     *            RSA public key for encryption
     * @return Hexadecimal representation of encrypted message
     */
    public synchronized static byte[] encryptRSAString(final byte[] message, final byte[] publicKey) {
        byte[] retVal = null;
        init();
        KeyFactory factory;
        X509EncodedKeySpec pks;
        try {
            factory = KeyFactory.getInstance("RSA");
            pks = new X509EncodedKeySpec(publicKey);
            PublicKey pk = factory.generatePublic(pks);
            rsaCipher.init(Cipher.ENCRYPT_MODE, pk);
            retVal = rsaCipher.doFinal(message);
        } catch (InvalidKeyException e) {
            LOGGER.error("Invalid RSA public key specified", e);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("Invalid RSA key block specified", e);
        } catch (BadPaddingException e) {
            LOGGER.error("Bad RSA key padding specified", e);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Invalid crypting algorithm specified", e);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("Invalid RSA key specification declared", e);
        }
        return retVal;
    }

    /**
     * @param message
     *            A message as a byte array that will be decrypted with class
     *            defined RSA private key
     * @return Decrypted message as a plain text
     */
    public synchronized static byte[] decryptRSAString(final byte[] message) {
        byte[] retVal = null;
        init();
        try {
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            retVal = rsaCipher.doFinal(message);
        } catch (InvalidKeyException e) {
            LOGGER.error("Invalid RSA public key specified", e);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("Invalid RSA key block specified", e);
        } catch (BadPaddingException e) {
            LOGGER.error("Bad RSA key padding specified", e);
        }
        return retVal;
    }

    /**
     * Extracts AES key that is encrypted by class defined RSA public key
     * 
     * @param identifier
     *            AES key identifier
     * @param encrypted
     *            RSA encrypted AES key as a byte array
     */
    public synchronized static void extractAESKey(final String identifier, final byte[] encrypted) {
        init();
        try {
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            byte[] aesKey = rsaCipher.doFinal(encrypted);
            SecretKey secretKey = new SecretKeySpec(aesKey, "AES");
            Cipher c2 = Cipher.getInstance("AES/ECB/NoPadding");
            c2.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] bText = c2.doFinal(aesKey);
            secretKey = new SecretKeySpec(bText, "AES");
            aesKeyMap.put(identifier, secretKey);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("Invalid AES key block specified", e);
        } catch (BadPaddingException e) {
            LOGGER.error("Bad AES key padding specified", e);
        } catch (InvalidKeyException e) {
            LOGGER.error("Invalid RSA private block specified", e);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Invalid algorithm specified", e);
        } catch (NoSuchPaddingException e) {
            LOGGER.error("Invalid padding specified", e);
        }
    }

    /**
     * @param identifier
     *            Identifies secure key storage
     * @param message
     *            AES encrypted message Base64 encoded
     * @return Decrypted plain text message
     */
    public synchronized static String decryptAESMessage(final String identifier, final String message) {
        return getAESMessage(Cipher.DECRYPT_MODE, identifier, message);
    }

    /**
     * @param identifier
     *            Identifies secure key storage
     * @param message
     *            UTF-8 encoded message
     * @return AES encrypted message Base 64 encoded
     */
    public synchronized static String encryptAESMessage(final String identifier, final String message) {
        return getAESMessage(Cipher.ENCRYPT_MODE, identifier, message);
    }

    private synchronized static String getAESMessage(final int cipherMode, final String identifier, final String message) {
        String retVal = null;
        init();
        try {
            Cipher aesCipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            if (cipherMode == 1) {
                SecureRandom random = new SecureRandom();
                byte[] ivBytes = new byte[BYTE];
                random.nextBytes(ivBytes);
                IvParameterSpec nonce = new IvParameterSpec(Arrays.copyOf(ivBytes, DOUBLE_BYTE));
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKeyMap.get(identifier), nonce);
                byte[] encrypted = aesCipher.doFinal(message.getBytes(PLAIN_TEXT_ENCODING));
                byte[] ciphertext = Arrays.copyOf(ivBytes, ivBytes.length + encrypted.length);
                for (int i = 0; i < encrypted.length; i++) {
                    ciphertext[i + BYTE] = encrypted[i];
                }
                retVal = Base64.encodeToString(ciphertext);
            } else {
                byte[] ciphertextBytes = Base64.decode(message);
                byte[] ivBytes = Arrays.copyOf(Arrays.copyOf(ciphertextBytes, BYTE), DOUBLE_BYTE);
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKeyMap.get(identifier), new IvParameterSpec(ivBytes));
                byte[] recoveredCleartext = aesCipher.doFinal(ciphertextBytes, BYTE, ciphertextBytes.length - BYTE);
                retVal = new String(recoveredCleartext);
            }
        } catch (InvalidKeyException e) {
            LOGGER.error("Invalid AES key specified", e);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("Invalid AES message block specified", e);
        } catch (BadPaddingException e) {
            LOGGER.error("Bad AES message padding specified", e);
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.error("Bad AES parameter specified", e);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Bad AES algorithm specified", e);
        } catch (NoSuchPaddingException e) {
            LOGGER.error("Bad AES padding specified", e);
        }
        return retVal;
    }

    private synchronized static void init() {
        if (rsaPrivateKey == null) {
            try {
                generateRSAKeys();
                rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error("Invalid crypting algorithm specified", e);
            } catch (NoSuchPaddingException e) {
                LOGGER.error("Invalid algorithm padding specified", e);
            }
        }
    }

    private synchronized static void generateRSAKeys() {
        RSAMultiPrimePrivateCrtKeySpec keySpec = new RSAMultiPrimePrivateCrtKeySpec(
                        new BigInteger(KEYHEX[0], DOUBLE_BYTE),
                        new BigInteger(KEYHEX[1], DOUBLE_BYTE),
                        new BigInteger(KEYHEX[2], DOUBLE_BYTE),
                        new BigInteger(KEYHEX[3], DOUBLE_BYTE),
                        new BigInteger(KEYHEX[4], DOUBLE_BYTE),
                        new BigInteger(KEYHEX[5], DOUBLE_BYTE),
                        new BigInteger(KEYHEX[6], DOUBLE_BYTE),
                        new BigInteger(KEYHEX[7], DOUBLE_BYTE), null);
        KeyFactory factory;
        spec = new RSAPublicKeySpec(keySpec.getModulus(), keySpec.getPublicExponent());
        try {
            factory = KeyFactory.getInstance("RSA");
            rsaPrivateKey = (RSAPrivateKey) factory.generatePrivate(keySpec);
            rsaPublicKey = (RSAPublicKey) factory.generatePublic(spec);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Invalid crypting algorithm specified", e);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("Invalid key specification declared", e);
        }
    }
}
