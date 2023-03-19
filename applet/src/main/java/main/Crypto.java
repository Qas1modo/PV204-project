package main;

import javacard.security.*;
import javacardx.crypto.Cipher;
import java.security.SecureRandom;

public class Crypto {
    final public short AES_BLOCK_SIZE = 16;
    public final short SC_KEY_LENGTH = 256;
    public final short SC_SECRET_LENGTH = 32;
    public AESKey scEncKey;
    public AESKey scMacKey;
    public SecureRandom random;
    public KeyAgreement ecdh;
    public MessageDigest sha256;
    public MessageDigest sha512;
    public Cipher aes;
    public Signature mac;
    public byte[] pairingSecret;
    public KeyPair scKeypair;
    public final byte PIN_LENGTH = 6;
    public final byte PUK_LENGTH = 10;
    public final short SC_BLOCK_SIZE = 16;
    public final short INIT_ENC_LEN = PIN_LENGTH + PUK_LENGTH + SC_SECRET_LENGTH;
    public final short INIT_AES_LEN = (INIT_ENC_LEN / SC_BLOCK_SIZE + 1) * SC_BLOCK_SIZE;
    public Crypto() {
        random = new SecureRandom();
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        aes = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);
        mac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
        scEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_256, false);
        scMacKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_256, false);
        pairingSecret = new byte[(short)SC_SECRET_LENGTH];
        scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
        scKeypair.genKeyPair();
    }

    public void genBytes(byte[] buffer, int offset, int length) {
        byte[] randomBuffer = new byte[length];
        random.nextBytes(randomBuffer);
        System.arraycopy(randomBuffer, 0, buffer, offset, length);
    }

}
