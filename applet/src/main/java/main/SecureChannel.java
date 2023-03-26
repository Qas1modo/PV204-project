package main;

import javacard.framework.ISO7816;
import javacard.security.ECPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.DigestException;
import java.util.Arrays;

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
        crypto.random.nextBytes(challenge);
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
        response = Run.simulator.transmitCommand(commandAPDU);
        if (!Arrays.equals(response.getData(), challengeResponse)) {
            reset();
            return false;
        }
        return true;
    }

    //USE THIS TO RESPOND BY SECURE CHANNEL
    public ResponseAPDU secureRespond(byte[] input, short len, byte instruction, byte P1, byte P2) {
        short cipher_len = (short) (((len + 1) / Const.AES_BLOCK_SIZE + 1) * Const.AES_BLOCK_SIZE);
        byte[] request = new byte[ISO7816.OFFSET_CDATA + Const.AES_BLOCK_SIZE + cipher_len];
        crypto.aes.init(crypto.scEncKey, Cipher.MODE_ENCRYPT, secret_IV, (short) 0, Const.SC_BLOCK_SIZE);
        len = crypto.aes.doFinal(input, (short) 0, len, request, (short) (ISO7816.OFFSET_CDATA + Const.SC_BLOCK_SIZE));
        request[0] = Const.CLA_SIMPLE_APPLET;
        request[1] = instruction;
        request[2] = P1;
        request[3] = P2;
        request[4] = (byte) (len + Const.AES_BLOCK_SIZE);
        computeMAC(request, len);
        System.arraycopy(request, ISO7816.OFFSET_CDATA, secret_IV, 0, Const.SC_BLOCK_SIZE);
        CommandAPDU commandAPDU = new CommandAPDU(request, (short) 0, request.length);
        return Run.simulator.transmitCommand(commandAPDU);
    }

    public short computeMAC(byte[] buffer, short len) {
        crypto.mac.init(crypto.scMacKey, Signature.MODE_SIGN);
        crypto.mac.update(buffer, (short) 0, ISO7816.OFFSET_CDATA);
        crypto.mac.update(secret_IV, Const.SC_BLOCK_SIZE, (short) (Const.SC_BLOCK_SIZE - ISO7816.OFFSET_CDATA)); // zero padding
        return crypto.mac.sign(buffer, (short) (ISO7816.OFFSET_CDATA + Const.SC_BLOCK_SIZE), len,
                buffer, ISO7816.OFFSET_CDATA);
    }

    //USE THIS TO RECEIVE DATA FROM SECURE CHANNEL
    public short verifyAndDecrypt(byte[] buffer) {
        short apduLen = (short) buffer.length;
        if (!verifyMAC(buffer, apduLen)) {
            reset();
            throw new RuntimeException();
        }
        crypto.aes.init(crypto.scEncKey, Cipher.MODE_DECRYPT, secret_IV, (short) 0, Const.SC_BLOCK_SIZE);
        System.arraycopy(buffer, 0, secret_IV, 0, Const.SC_BLOCK_SIZE);
        return crypto.aes.doFinal(buffer, Const.SC_BLOCK_SIZE,
                (short) (apduLen - Const.SC_BLOCK_SIZE) , buffer, (short) 0);
    }

    public boolean verifyMAC(byte[] buffer, short len) {
        crypto.mac.init(crypto.scMacKey, Signature.MODE_VERIFY);
        return crypto.mac.verify(buffer, Const.AES_BLOCK_SIZE, (short) (len - Const.AES_BLOCK_SIZE),
                buffer, (short) 0, Const.AES_BLOCK_SIZE);
    }

    public void openSc() throws DigestException {
        byte[] request_data = new byte[Const.EC_KEY_LEN];
        crypto.scKeypair.genKeyPair();
        crypto.ecdh.init(crypto.scKeypair.getPrivate());
        ECPublicKey pk = (ECPublicKey) crypto.scKeypair.getPublic();
        short length = pk.getW(request_data, (short) 0);
        if (length != Const.EC_KEY_LEN) {
            throw new RuntimeException("Keys are different length");
        }
        CommandAPDU commandAPDU = new CommandAPDU(0x00, Const.INS_OPEN_SC, 0x00, 0x00, request_data);
        ResponseAPDU responseAPDU = Run.simulator.transmitCommand(commandAPDU);
        byte[] response = responseAPDU.getData();
        try {
            length = crypto.ecdh.generateSecret(response, (short) (Const.AES_BLOCK_SIZE + Const.SC_SECRET_LENGTH),
                    Const.EC_KEY_LEN, secret_IV, (short) 0);
        } catch (Exception e){
            throw new RuntimeException();
        }
        crypto.sha512.update(secret_IV, 0, length);
        crypto.sha512.update(pairingSecret, 0, Const.SC_SECRET_LENGTH);
        crypto.sha512.update(response, 0, Const.SC_SECRET_LENGTH);
        crypto.sha512.digest(secret_IV, 0, 64);
        crypto.scEncKey.setKey(secret_IV, (short) 0);
        crypto.scMacKey.setKey(secret_IV, Const.SC_SECRET_LENGTH);
        System.arraycopy(response, Const.SC_SECRET_LENGTH, secret_IV, (short) 0, Const.SC_BLOCK_SIZE);
        Arrays.fill(secret_IV, Const.SC_BLOCK_SIZE,
                2*Const.SC_SECRET_LENGTH, (byte) 0); // fill zero
        scOpened = true;
    }

    public ResponseAPDU initialize(byte[] response) throws DigestException {
        byte[] data_to_encrypt = new byte[Const.INIT_ENC_LEN];
        crypto.ecdh.init(crypto.scKeypair.getPrivate());
        short pk_len = (short) (response.length - 3);
        try {
            crypto.ecdh.generateSecret(response, (short) 1, pk_len, secret_IV, (short) 0);
        } catch (Exception e) {
            System.out.println("Invalid PK received");
            return null;
        }
        ECPublicKey pk = (ECPublicKey) crypto.scKeypair.getPublic();
        byte[] request_data = new byte[pk_len + Const.AES_BLOCK_SIZE + Const.INIT_AES_LEN];
        short mpk_len = pk.getW(request_data, (short) 0);
        if (mpk_len != pk_len) {
            throw new RuntimeException("Keys are different length");
        }
        System.arraycopy(UserInterface.getPin(false), 0, data_to_encrypt, 0, Const.PIN_LENGTH);
        System.arraycopy(UserInterface.getPuk(false), 0, data_to_encrypt, Const.PIN_LENGTH, Const.PUK_LENGTH);
        crypto.genBytes(data_to_encrypt, Const.PIN_LENGTH + Const.PUK_LENGTH, Const.SC_SECRET_LENGTH);
        crypto.sha256.update(data_to_encrypt, Const.PIN_LENGTH + Const.PUK_LENGTH, Const.SC_SECRET_LENGTH);
        crypto.sha256.digest(pairingSecret, 0, 32);
        crypto.genBytes(request_data, pk_len, Const.AES_BLOCK_SIZE);
        crypto.scEncKey.setKey(secret_IV, (short) 0);
        crypto.aes.init(crypto.scEncKey, Cipher.MODE_ENCRYPT, request_data, pk_len, Const.AES_BLOCK_SIZE);
        crypto.aes.doFinal(data_to_encrypt, (short) 0, Const.INIT_ENC_LEN, request_data,
                (short) (pk_len + Const.AES_BLOCK_SIZE));
        CommandAPDU commandAPDU = new CommandAPDU(0x00, Const.INS_INIT, 0x00, 0x00, request_data);
        return Run.simulator.transmitCommand(commandAPDU);
    }

    public char getState() {
        if (pinBlocked) {
            return '!';
        }
        if (pinVerified) {
            return 'V';
        }
        if (permanentlyBlocked) {
            return '#';
        }
        return 'X';
    }

    public void changePS(byte[] buffer, int off, int len) {
        crypto.sha256.update(buffer, off, len);
        try {
            crypto.sha256.digest(pairingSecret, 0, 32);
        } catch (Exception e) {
            System.out.println("Digest error");
            return;
        }
        System.out.println("New pairing secret:");
        System.out.println(Arrays.toString(pairingSecret));
        reset();
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
        crypto.scEncKey.clearKey();
        crypto.scMacKey.clearKey();
        crypto.scKeypair.genKeyPair();
        scOpened = false;
        pinVerified = false;
    }
}
