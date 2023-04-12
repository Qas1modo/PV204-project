package main;


import javax.crypto.SecretKey;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import applet.SecP256k1;
import javacard.security.*;
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class Crypto {
    private SecretKey scEncKey;
    public AESKey scMacKey;
    private final SecureRandom random;
    private final KeyAgreement ecdh;
    public final MessageDigest sha256;
    public final MessageDigest sha512;
    private final Cipher aes;
    public final Signature mac;
    private final KeyPair scKeypair;

    public Crypto() {
        try {
            random = new SecureRandom();
            sha256 = java.security.MessageDigest.getInstance("SHA-256");
            sha512 = java.security.MessageDigest.getInstance("SHA-512");
            aes = Cipher.getInstance("AES/CBC/NoPadding");
            ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
            mac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
            scMacKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                    KeyBuilder.LENGTH_AES_256, false);
            scKeypair = new KeyPair(KeyPair.ALG_EC_FP, Const.SC_KEY_LENGTH);
            SecP256k1.setCurveParameters((ECKey) scKeypair.getPrivate());
            SecP256k1.setCurveParameters((ECKey) scKeypair.getPublic());
            scKeypair.genKeyPair();
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    public int exportKey(byte[] buffer, int off) {
        ECPublicKey pk = (ECPublicKey) scKeypair.getPublic();
        short length = pk.getW(buffer, (short) off);
        if (length != Const.EC_KEY_LEN) {
            throw new RuntimeException("Keys are different length");
        }
        return length;
    }

    public int generateSecret(byte[] input, int off, byte[] output, int outOff) {
        ecdh.init(scKeypair.getPrivate());
        return ecdh.generateSecret(input, (short) off, Const.EC_KEY_LEN, output, (short) outOff);
    }

    public void genKeyPair(){
        scKeypair.genKeyPair();
    }

    public void setEncKey(byte[] key, int off) {
        scEncKey = new SecretKeySpec(key, off, Const.SC_KEY_LENGTH / 8, "AES");
    }

    public void genBytes(byte[] buffer, int offset, int length) {
        byte[] randomBuffer = new byte[length];
        random.nextBytes(randomBuffer);
        System.arraycopy(randomBuffer, 0, buffer, offset, length);
    }

    public int encrypt(byte[] input, int inputOff, int inputLen, byte[] output, int outputOff,
                          byte[] iv, int ivOff) throws Exception {
        int newArraySize = (((inputLen + 1)/ 16) + 1) * Const.AES_BLOCK_SIZE;
        byte[] inputPadded = new byte[newArraySize];
        System.arraycopy(input, inputOff, inputPadded, 0, inputLen);
        inputPadded[inputLen] = (byte)0x80;
        aes.init(Cipher.ENCRYPT_MODE, scEncKey ,new IvParameterSpec(iv, ivOff, Const.AES_BLOCK_SIZE));
        return aes.doFinal(inputPadded, 0, newArraySize, output, outputOff);
    }

    public int decrypt(byte[] input, int inputOff, int inputLen, byte[] output, int outputOff,
                          byte[] iv, int ivOff) throws Exception {
        byte[] transientArray = new byte[inputLen];
        aes.init(Cipher.DECRYPT_MODE, scEncKey ,new IvParameterSpec(iv, ivOff, Const.AES_BLOCK_SIZE));
        int outLen =  aes.doFinal(input, inputOff, inputLen, transientArray, 0);
        byte padding;
        for (int i = outLen - 1; i >= 0; i--) {
            padding = transientArray[i];
            if (padding == (byte) 0x80) {
                System.arraycopy(transientArray, 0, output, outputOff, i);
                return i;
            }
        }
        return -1;
    }

    public void reset() {
        scMacKey.clearKey();
        scEncKey = null;
        scKeypair.genKeyPair();
    }
}
