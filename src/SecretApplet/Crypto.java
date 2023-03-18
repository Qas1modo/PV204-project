package SecretApplet;

import javacard.security.*;
import javacardx.crypto.Cipher;

public class Crypto {
    final static public short AES_BLOCK_SIZE = 16;
    public RandomData random;
    public KeyAgreement ecdh;
    public MessageDigest sha256;
    public MessageDigest sha512;
    public Cipher aes;
    public Signature mac;

    Crypto() {
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        aes = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5,false);
        mac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
    }
}
