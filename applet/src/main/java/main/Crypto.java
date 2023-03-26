package main;

import javacard.security.*;
import javacardx.crypto.Cipher;
import java.security.SecureRandom;

public class Crypto {
    public AESKey scEncKey;
    public AESKey scMacKey;
    public SecureRandom random;
    public KeyAgreement ecdh;
    public java.security.MessageDigest sha256;
    public java.security.MessageDigest sha512;
    public Cipher aes;
    public Signature mac;
    public byte[] pairingSecret;
    public KeyPair scKeypair;

    public Crypto() {
        try {
            random = new SecureRandom();
            sha256 = java.security.MessageDigest.getInstance("SHA-256");
            ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
            sha512 = java.security.MessageDigest.getInstance("SHA-512");
            aes = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);
            mac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
            scEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                    KeyBuilder.LENGTH_AES_256, false);
            scMacKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                    KeyBuilder.LENGTH_AES_256, false);
            pairingSecret = new byte[Const.SC_SECRET_LENGTH];
            scKeypair = new KeyPair(KeyPair.ALG_EC_FP, Const.SC_KEY_LENGTH);
            scKeypair.genKeyPair();
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }


    public void genBytes(byte[] buffer, int offset, int length) {
        byte[] randomBuffer = new byte[length];
        random.nextBytes(randomBuffer);
        System.arraycopy(randomBuffer, 0, buffer, offset, length);
    }
}
