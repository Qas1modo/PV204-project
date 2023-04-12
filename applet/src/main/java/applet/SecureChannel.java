package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class SecureChannel {

    //KEYS
    private final AESKey scEncKey;
    private final AESKey scMacKey;
    private final KeyPair scKeypair;
    private final Crypto crypto;

    //STATES
    public boolean authenticated = false;
    public boolean firstPhaseCompleted = false;
    private final byte[] secret_IV;
    private final byte[] pairingSecret;
    private final byte[] rand;

    private final byte[] antiBug;

    //CONSTANTS
    public final static byte SC_SECRET_LENGTH = 32;
    public final short MAX_RESPONSE_LENGTH = 240;
    public static final short INIT_ENC_LEN = SecretStorageApplet.PIN_LENGTH + SecretStorageApplet.PUK_LENGTH
            + SecureChannel.SC_SECRET_LENGTH;
    public final short SC_KEY_LENGTH = 256;
    public final short SC_BLOCK_SIZE = Crypto.AES_BLOCK_SIZE;
    public final short INIT_AES_LEN = ((SecretStorageApplet.PIN_LENGTH +
            SecretStorageApplet.PUK_LENGTH + SC_SECRET_LENGTH) / SC_BLOCK_SIZE + 1) *SC_BLOCK_SIZE;
    public final short INIT_FIX_LENGTH = INIT_AES_LEN + SC_BLOCK_SIZE;

    //P1 CONSTANTS
    public final byte VERIFICATION_FIRST_STEP = 0;
    public final byte VERIFICATION_SECOND_STEP = 1;

    public SecureChannel() {
        crypto = new Crypto();
        scEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_256, false);
        scMacKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_256, false);
        secret_IV = JCSystem.makeTransientByteArray((short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
        rand = JCSystem.makeTransientByteArray((short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
        pairingSecret = new byte[SC_SECRET_LENGTH];
        antiBug = JCSystem.makeTransientByteArray(MAX_RESPONSE_LENGTH, JCSystem.CLEAR_ON_DESELECT); // Need to fix error - consultation
        scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
        SecP256k1.setCurveParameters((ECKey) scKeypair.getPrivate());
        SecP256k1.setCurveParameters((ECKey) scKeypair.getPublic());
        scKeypair.genKeyPair();
    }

    public void decryptInit(byte[] buffer) {
        crypto.ecdh.init(scKeypair.getPrivate());
        short pk_len = (short) ((buffer[ISO7816.OFFSET_LC] & 0xff) - INIT_FIX_LENGTH);
        short offset = ISO7816.OFFSET_CDATA;
        try {
            crypto.ecdh.generateSecret(buffer, offset, pk_len, secret_IV, (short) 0);
            offset += pk_len;
        } catch(Exception e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        scEncKey.setKey(secret_IV, (short) 0);
        crypto.aes.init(scEncKey, Cipher.MODE_DECRYPT, buffer, offset, Crypto.AES_BLOCK_SIZE);
        offset += Crypto.AES_BLOCK_SIZE;
        buffer[ISO7816.OFFSET_LC] = (byte) crypto.aes.doFinal(buffer, offset, INIT_AES_LEN,
                buffer, ISO7816.OFFSET_CDATA);
    }

    public void initSC(byte[] buffer, short offset) {
        updatePairingSecret(buffer, offset);
    }

    public void openSC(APDU apdu, byte[] buffer) {
        scKeypair.genKeyPair();
        crypto.ecdh.init(scKeypair.getPrivate());
        authenticated = false;
        short length;
        try {
             length = crypto.ecdh.generateSecret(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC],
                     secret_IV, (short) 0);
        } catch (Exception e){
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        crypto.random.generateData(buffer, (short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
        crypto.sha512.update(secret_IV, (short) 0, length);
        crypto.sha512.update(pairingSecret, (short) 0, SC_SECRET_LENGTH);
        crypto.sha512.doFinal(buffer, (short) 0, SC_SECRET_LENGTH, secret_IV, (short) 0);
        scEncKey.setKey(secret_IV, (short) 0);
        scMacKey.setKey(secret_IV, SC_SECRET_LENGTH);
        Util.arrayCopyNonAtomic(buffer, SC_SECRET_LENGTH, secret_IV, (short) 0, SC_BLOCK_SIZE);
        Util.arrayFillNonAtomic(secret_IV, SC_BLOCK_SIZE, (short) (2*SC_SECRET_LENGTH - SC_BLOCK_SIZE), (byte) 0); // fill zero
        short pkLen = copyPublicKey(buffer, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
        apdu.setOutgoingAndSend((short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE + pkLen));
    }

    public void verifyKeys(APDU apdu, byte[] buffer) {
        if (authenticated || !scEncKey.isInitialized() || !scMacKey.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buffer[ISO7816.OFFSET_P1] == VERIFICATION_FIRST_STEP) {
            short len = verify_and_decrypt(buffer);
            if (len != SC_SECRET_LENGTH) {
                reset();
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, rand, (short) 0, SC_SECRET_LENGTH);
            crypto.random.generateData(rand, SC_SECRET_LENGTH, SC_SECRET_LENGTH);
            Util.arrayCopy(rand, SC_SECRET_LENGTH, buffer, (short) 0, SC_SECRET_LENGTH);
            firstPhaseCompleted = true;
            secureRespond(apdu, buffer, SC_SECRET_LENGTH);
        } else if (buffer[ISO7816.OFFSET_P1] == VERIFICATION_SECOND_STEP && firstPhaseCompleted) {
            if(buffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH) {
                reset();
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            byte challenge = Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, rand, SC_SECRET_LENGTH, SC_SECRET_LENGTH);
            if (challenge != 0) {
                reset();
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            Util.arrayCopyNonAtomic(rand, (short) 0, buffer, (short) 0, SC_SECRET_LENGTH);
            authenticated = true;
            apdu.setOutgoingAndSend((short) 0, SC_SECRET_LENGTH);
        } else {
            reset();
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    //Use this method to get data from secure channel
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

    // Use this to send data over secure channel
    public void secureRespond(APDU apdu, byte[] apduBuffer, short len) {
        crypto.aes.init(scEncKey, Cipher.MODE_ENCRYPT, secret_IV, (short) 0, SC_BLOCK_SIZE);
        len = crypto.aes.doFinal(apduBuffer, (short) 0, len, antiBug,  (short) 0);
        computeMAC(len, apduBuffer, antiBug);
        Util.arrayCopyNonAtomic(apduBuffer, (short) 0, secret_IV, (short) 0, SC_BLOCK_SIZE);
        Util.arrayCopyNonAtomic(antiBug, (short) 0, apduBuffer, SC_BLOCK_SIZE, len);
        len += SC_BLOCK_SIZE;
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void computeMAC(short len, byte[] apduBuffer, byte[] buffer) {
        crypto.mac.init(scMacKey, Signature.MODE_SIGN);
        crypto.mac.sign(buffer, (short) 0, len, apduBuffer, (short) 0);
    }

/*    public void secureRespond(APDU apdu, byte[] buffer, short len) {
        crypto.aes.init(scEncKey, Cipher.MODE_ENCRYPT, secret_IV, (short) 0, SC_BLOCK_SIZE);
        len = crypto.aes.doFinal(buffer, (short) 0, len, buffer, SC_BLOCK_SIZE);
        computeMAC(buffer, len);
        Util.arrayCopyNonAtomic(buffer, (short) 0, secret_IV, (short) 0, SC_BLOCK_SIZE);
        len += SC_BLOCK_SIZE;
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void computeMAC(byte[] buffer, short len) {
        crypto.mac.init(scMacKey, Signature.MODE_SIGN);
        crypto.mac.sign(buffer, SC_BLOCK_SIZE, len, buffer, (short) 0);
    }*/

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
        authenticated = false;
        firstPhaseCompleted = false;
        scKeypair.genKeyPair();
    }

    public void removePairingSecret() {
        Util.arrayFillNonAtomic(pairingSecret, (short) 0, SC_SECRET_LENGTH, (byte) 0);
    }
}
