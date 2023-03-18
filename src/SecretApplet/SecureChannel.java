package SecretApplet;

import javacard.security.*;
import javacardx.crypto.Cipher;
import javacard.framework.*;

public class SecureChannel {

    //KEYS
    private AESKey scEncKey;
    private HMACKey scMacKey;
    private KeyPair scKeypair;
    private byte[] secret_IV;

    //STATES
    private boolean authenticated = false;
    private byte[] pairingSecret;
    private byte[] rand;

    //CONSTANTS
    public final byte SC_SECRET_LENGTH = 32;
    public final short SC_KEY_LENGTH = 256;
    public final short SC_BLOCK_SIZE = Crypto.AES_BLOCK_SIZE;
    public final short INIT_AES_LEN = ((SecretStorage.PIN_LENGTH + SecretStorage.PUK_LENGTH + SC_SECRET_LENGTH)
            / SC_BLOCK_SIZE + 1) *SC_BLOCK_SIZE;
    public final short INIT_FIX_LENGTH = INIT_AES_LEN + SC_BLOCK_SIZE;

    public final short VERIFICATION_FIRST_STEP = 0;
    public final short VERIFICATION_SECOND_STEP = 1;

    private final Crypto crypto;

    public SecureChannel(Crypto crypto) {
        this.crypto = crypto;
        scEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_256, false);
        scMacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_256, false);
        secret_IV = JCSystem.makeTransientByteArray((short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
        rand = JCSystem.makeTransientByteArray((short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
        pairingSecret = new byte[(short)SC_SECRET_LENGTH];
        scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
        SECP256k1.setCurveParameters((ECKey) scKeypair.getPrivate());
        SECP256k1.setCurveParameters((ECKey) scKeypair.getPublic());
        scKeypair.genKeyPair();
    }

    public void decryptInit(byte[] apduBuffer) {
        crypto.ecdh.init(scKeypair.getPrivate());
        short pk_len = (short) ((apduBuffer[ISO7816.OFFSET_LC] & 0xff) - INIT_FIX_LENGTH);
        short offset = ISO7816.OFFSET_CDATA;
        try {
            crypto.ecdh.generateSecret(apduBuffer, offset, pk_len, secret_IV, (short) 0);
            offset += pk_len;
        } catch(Exception e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        scEncKey.setKey(secret_IV, (short) 0);
        crypto.aes.init(scEncKey, Cipher.MODE_DECRYPT, apduBuffer, offset, Crypto.AES_BLOCK_SIZE);
        offset += Crypto.AES_BLOCK_SIZE;
        apduBuffer[ISO7816.OFFSET_LC] = (byte) crypto.aes.doFinal(apduBuffer, offset, INIT_AES_LEN,
                apduBuffer, ISO7816.OFFSET_CDATA);
    }

    public void initSC(byte[] buffer, short offset) {
        updatePairingSecret(buffer, offset);
        scKeypair.genKeyPair();
    }

    public void openSC(APDU apdu) {
        authenticated = false;
        byte[] apduBuffer = apdu.getBuffer();
        crypto.ecdh.init(scKeypair.getPrivate());
        short length;
        try {
             length = crypto.ecdh.generateSecret(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer[ISO7816.OFFSET_LC],
                     secret_IV, (short) 0);
        } catch (Exception e){
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        crypto.random.generateData(apduBuffer, (short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
        crypto.sha512.update(secret_IV, (short) 0, length);
        crypto.sha512.update(pairingSecret, (short) 0, SC_SECRET_LENGTH);
        crypto.sha512.doFinal(apduBuffer, (short) 0, SC_SECRET_LENGTH, secret_IV, (short) 0);
        scEncKey.setKey(secret_IV, (short) 0);
        scMacKey.setKey(secret_IV, SC_SECRET_LENGTH, SC_SECRET_LENGTH);
        Util.arrayCopyNonAtomic(apduBuffer, SC_SECRET_LENGTH, secret_IV, (short) 0, SC_BLOCK_SIZE);
        Util.arrayFillNonAtomic(secret_IV, SC_BLOCK_SIZE, (short) (2*SC_SECRET_LENGTH - SC_BLOCK_SIZE), (byte) 0); // fill zero
        apdu.setOutgoingAndSend((short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
    }

    public void verifyKeys(APDU apdu) {
        if (authenticated || !scEncKey.isInitialized() || !scMacKey.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] apduBuffer = apdu.getBuffer();
        if (apduBuffer[ISO7816.OFFSET_P1] == VERIFICATION_FIRST_STEP) {
            short len = verify_and_decrypt(apduBuffer);
            if (len != SC_SECRET_LENGTH) {
                reset();
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, rand, (short) 0, SC_SECRET_LENGTH);
            crypto.random.generateData(apduBuffer, ISO7816.OFFSET_CDATA, SC_SECRET_LENGTH);
            Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, rand, SC_SECRET_LENGTH, SC_SECRET_LENGTH);
            secureRespond(apdu, SC_SECRET_LENGTH, ISO7816.SW_NO_ERROR);
        } else if (apduBuffer[ISO7816.OFFSET_P1] == VERIFICATION_SECOND_STEP) {
            if(apduBuffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH) {
                reset();
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            byte challenge = Util.arrayCompare(apduBuffer, ISO7816.OFFSET_CDATA, rand, SC_SECRET_LENGTH, SC_SECRET_LENGTH);
            if (challenge != 0) {
                reset();
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            Util.arrayCopyNonAtomic(rand, (short) 0, apduBuffer, (short) 0, SC_SECRET_LENGTH);
            authenticated = true;
            apdu.setOutgoingAndSend((short) 0, SC_SECRET_LENGTH);
        } else {
            reset();
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    public short processAPDU(byte[] buffer) {
        if (!isOpen()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        return verify_and_decrypt(buffer);
    }

    private short verify_and_decrypt(byte[] buffer) {
        short apduLen = (short)((short) buffer[ISO7816.OFFSET_LC] & 0xff);
        if (!verifyMAC(buffer, apduLen)) {
            reset();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        crypto.aes.init(scEncKey, Cipher.MODE_DECRYPT, secret_IV, (short) 0, SC_BLOCK_SIZE);
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, secret_IV, (short) 0, SC_BLOCK_SIZE);
        short len = crypto.aes.doFinal(buffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE),
                (short) (apduLen - SC_BLOCK_SIZE) , buffer, ISO7816.OFFSET_CDATA);
        buffer[ISO7816.OFFSET_LC] = (byte) len;
        return len;
    }

    private boolean verifyMAC(byte[] buffer, short apduLen) {
        crypto.mac.init(scMacKey, Signature.MODE_VERIFY);
        crypto.mac.update(buffer, (short) 0, ISO7816.OFFSET_CDATA);
        crypto.mac.update(secret_IV, SC_BLOCK_SIZE, (short) (SC_BLOCK_SIZE - ISO7816.OFFSET_CDATA)); // zero padding
        return crypto.mac.verify(buffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE),
                (short) (apduLen - SC_BLOCK_SIZE), buffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
    }

    public boolean isOpen() {
        return scEncKey.isInitialized() && scMacKey.isInitialized() && authenticated ;
    }

    public void secureRespond(APDU apdu, short len, short sw) {
        byte[] apduBuffer = apdu.getBuffer();
        Util.setShort(apduBuffer, (short) (ISO7816.OFFSET_CDATA + len), sw);
        len += 2;
        crypto.aes.init(scEncKey, Cipher.MODE_ENCRYPT, secret_IV, (short) 0, SC_BLOCK_SIZE);
        len = crypto.aes.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, len, apduBuffer,
                (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE));
        computeMAC(len, apduBuffer);
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret_IV, (short) 0, SC_BLOCK_SIZE);
        len += SC_BLOCK_SIZE;
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
    }

    private void computeMAC(short len, byte[] apduBuffer) {
        crypto.mac.init(scMacKey, Signature.MODE_SIGN);
        crypto.mac.sign(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), len,
                apduBuffer, ISO7816.OFFSET_CDATA);
    }

    public short copyPublicKey(byte[] buf, short off) {
        ECPublicKey pk = (ECPublicKey) scKeypair.getPublic();
        return pk.getW(buf, off);
    }

    public void updatePairingSecret(byte[] buffer, short offset) {
        crypto.sha256.doFinal(buffer, offset, SC_SECRET_LENGTH, pairingSecret, (short) 0);
    }

    public void reset() {
        scEncKey.clearKey();
        scMacKey.clearKey();
        Util.arrayFillNonAtomic(rand, (short) 0, (short) (2 * SC_BLOCK_SIZE), (byte) 0);
        authenticated = false;
        scKeypair.genKeyPair();
    }
}
