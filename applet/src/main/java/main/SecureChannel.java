package main;

import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.Signature;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.lang.reflect.Array;
import java.security.DigestException;
import java.util.Arrays;
import java.util.Base64;

public class SecureChannel {

    //STATES
    private boolean scOpened = false;
    private boolean pinVerified = false;
    private boolean pinBlocked = false;
    private boolean permanentlyBlocked = false;
    public final Crypto crypto;

    //Data arrays
    private final byte[] secret_IV; //array containing initialization secret and IV
    private final byte[] challengeResponse;
    private final byte[] pairingSecret;


    public SecureChannel() {
        crypto = new Crypto();
        secret_IV = new byte[2* Const.SC_SECRET_LENGTH];
        pairingSecret = new byte[Const.SC_SECRET_LENGTH];
        challengeResponse = new byte[Const.SC_SECRET_LENGTH];
    }

    public boolean verifySc() {
        byte[] challenge = new byte[Const.SC_SECRET_LENGTH];
        crypto.genBytes(challenge, 0, Const.SC_SECRET_LENGTH);
        System.arraycopy(challenge, 0, challengeResponse, 0, Const.SC_SECRET_LENGTH);
        ResponseAPDU response = secureRespond(challenge, (short) challenge.length, Const.INS_VERIFY_KEYS,
                (byte)0x00, (byte)0x00);
        byte[] responseData = response.getData();
        int length = verifyAndDecrypt(responseData);
        if (length != Const.SC_SECRET_LENGTH) {
            reset();
            return false;
        }
        CommandAPDU commandAPDU = new CommandAPDU(0x00, Const.INS_VERIFY_KEYS, 0x01, 0x00, responseData,
                (short) 0, length);
        response = Run.transmit(commandAPDU);
        if (!Arrays.equals(response.getData(), challengeResponse)) {
            reset();
            return false;
        }
        return true;
    }

    //USE THIS TO RESPOND BY SECURE CHANNEL
    public ResponseAPDU secureRespond(byte[] input, int len, byte instruction, byte P1, byte P2) {
        int cipher_len = ((len + 1) / Const.AES_BLOCK_SIZE + 1) * Const.AES_BLOCK_SIZE;
        byte[] request = new byte[ISO7816.OFFSET_CDATA + Const.AES_BLOCK_SIZE + cipher_len];
        try {
            cipher_len = crypto.encrypt(input, 0, len, request,
                    ISO7816.OFFSET_CDATA + Const.SC_BLOCK_SIZE, secret_IV, 0);
        } catch (Exception e) {
            return null;
        }
        request[0] = Const.CLA_SIMPLE_APPLET;
        request[1] = instruction;
        request[2] = P1;
        request[3] = P2;
        request[4] = (byte) (cipher_len + Const.AES_BLOCK_SIZE);
        computeMAC(request, cipher_len);
        System.arraycopy(request, ISO7816.OFFSET_CDATA, secret_IV, 0, Const.SC_BLOCK_SIZE);
        CommandAPDU commandAPDU = new CommandAPDU(request, (short) 0, request.length);
        return Run.transmit(commandAPDU);
    }

    public short computeMAC(byte[] buffer, int len) {
        crypto.mac.init(crypto.scMacKey, Signature.MODE_SIGN);
        crypto.mac.update(buffer, (short) 0, ISO7816.OFFSET_CDATA);
        crypto.mac.update(secret_IV, Const.SC_BLOCK_SIZE, (short) (Const.SC_BLOCK_SIZE - ISO7816.OFFSET_CDATA)); // zero padding
        return crypto.mac.sign(buffer, (short) (ISO7816.OFFSET_CDATA + Const.SC_BLOCK_SIZE), (short) len,
                buffer, ISO7816.OFFSET_CDATA);
    }

    //USE THIS TO RECEIVE DATA FROM SECURE CHANNEL
    public int verifyAndDecrypt(byte[] buffer) {
        short apduLen = (short) buffer.length;
        if (!verifyMAC(buffer, apduLen)) {
            reset();
            throw new RuntimeException();
        }
        byte[] tempArray = secret_IV.clone();
        System.arraycopy(buffer, 0, secret_IV, 0, Const.SC_BLOCK_SIZE);
        try {
            return crypto.decrypt(buffer, Const.SC_BLOCK_SIZE, apduLen - Const.SC_BLOCK_SIZE, buffer, 0,
                    tempArray, 0);
        } catch (Exception e) {
            return -1;
        }
    }

    public boolean verifyMAC(byte[] buffer, short len) {
        crypto.mac.init(crypto.scMacKey, Signature.MODE_VERIFY);
        return crypto.mac.verify(buffer, Const.AES_BLOCK_SIZE, (short) (len - Const.AES_BLOCK_SIZE),
                buffer, (short) 0, Const.AES_BLOCK_SIZE);
    }

    public void openSc() throws DigestException {
        byte[] request_data = new byte[Const.EC_KEY_LEN];
        crypto.genKeyPair();
        crypto.exportKey(request_data, 0);
        CommandAPDU commandAPDU = new CommandAPDU(0x00, Const.INS_OPEN_SC, 0x00, 0x00, request_data);
        ResponseAPDU responseAPDU = Run.transmit(commandAPDU);
        byte[] response = responseAPDU.getData();
        int length;
        length = crypto.generateSecret(response, Const.AES_BLOCK_SIZE + Const.SC_SECRET_LENGTH, secret_IV,
                    0);
        crypto.sha512.update(secret_IV, 0, length);
        crypto.sha512.update(pairingSecret, 0, Const.SC_SECRET_LENGTH);
        crypto.sha512.update(response, 0, Const.SC_SECRET_LENGTH);
        crypto.sha512.digest(secret_IV, 0, 64);
        crypto.setEncKey(secret_IV, (short) 0);
        crypto.scMacKey.setKey(secret_IV, Const.SC_SECRET_LENGTH);
        System.arraycopy(response, Const.SC_SECRET_LENGTH, secret_IV, (short) 0, Const.SC_BLOCK_SIZE);
        Arrays.fill(secret_IV, Const.SC_BLOCK_SIZE,
                2*Const.SC_SECRET_LENGTH, (byte) 0); // fill zero
        scOpened = true;
    }

    public ResponseAPDU initialize(byte[] response) {
        byte[] data_to_encrypt = new byte[Const.INIT_ENC_LEN];
        crypto.generateSecret(response, 1, secret_IV, 0);
        byte[] request_data = new byte[Const.EC_KEY_LEN + Const.AES_BLOCK_SIZE + Const.INIT_AES_LEN];
        crypto.exportKey(request_data, 0);
        System.arraycopy(UserInterface.getPin(true), 0, data_to_encrypt, 0, Const.PIN_LENGTH);
        System.arraycopy(UserInterface.getPuk(true), 0, data_to_encrypt, Const.PIN_LENGTH, Const.PUK_LENGTH);
        crypto.genBytes(data_to_encrypt, Const.PIN_LENGTH + Const.PUK_LENGTH, Const.SC_SECRET_LENGTH);
        changePS(data_to_encrypt, Const.PIN_LENGTH + Const.PUK_LENGTH, Const.SC_SECRET_LENGTH);
        crypto.genBytes(request_data, Const.EC_KEY_LEN, Const.AES_BLOCK_SIZE);
        crypto.setEncKey(secret_IV, (short) 0);
        try {
            crypto.encrypt(data_to_encrypt, 0, Const.INIT_ENC_LEN, request_data,
                    Const.EC_KEY_LEN + Const.AES_BLOCK_SIZE, request_data, Const.EC_KEY_LEN);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt data");
        }
        CommandAPDU commandAPDU = new CommandAPDU(0x00, Const.INS_INIT, 0x00, 0x00, request_data);
        return Run.transmit(commandAPDU);
    }

    public char getState() {
        if (permanentlyBlocked) {
            return '#';
        }
        if (pinBlocked) {
            return '!';
        }
        if (pinVerified) {
            return 'V';
        }
        return 'X';
    }

    public void changePS(byte[] buffer, int off, int len) {
        System.out.print("Pairing secret (before hashing in Base64):");
        System.out.println(UserInterface.outputPS(buffer, off, len));
        crypto.sha256.update(buffer, off, len);
        try {
            crypto.sha256.digest(pairingSecret, 0, Const.SC_SECRET_LENGTH);
        } catch (Exception e) {
            System.out.println("Digest error");
        }
    }

    public boolean isOpened() {
        return scOpened;
    }

    public boolean isPinVerified() {
        return pinVerified;
    }

    public boolean isPinBlocked() {
        return pinBlocked;
    }
    public boolean isPermanentlyBlocked() {
        return permanentlyBlocked;
    }

    public void pinVerified(boolean value) {
        pinVerified = value;
    }
    public void pinBlocked(boolean value) {
        pinBlocked = value;
    }
    public void cardBlocked(boolean value) {
        permanentlyBlocked = value;
    }

    public void reset() {
        Arrays.fill(secret_IV, (byte)0);
        Arrays.fill(challengeResponse, (byte) 0);
        scOpened = false;
        pinVerified = false;
        crypto.reset();
    }
}
