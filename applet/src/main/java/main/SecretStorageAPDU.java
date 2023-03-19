package main;

import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;

public class SecretStorageAPDU {
    //CONSTANTS
    private final static byte EC_KEY_LEN = 65;

    //RETURN VALUES
    public final byte RET_NOT_INIT = (byte) 0xa0;
    public final byte RET_INITIALIZED = (byte) 0xa1;

    //SPECIFIC COMMANDS (P1)
    public final byte CHANGE_PIN = 0;
    public final byte CHANGE_PUK = 1;
    public final byte CHANGE_PAIRING_SECRET = 2;

    //INSTRUCTIONS
    private final byte CLA_SIMPLE_APPLET = (byte) 0x00;
    private final byte INS_INIT = (byte) 0x20;
    private final byte INS_OPEN_SC = (byte)0x21;
    private final byte INS_VERIFY_KEYS = (byte) 0x22;
    private final byte INS_CHANGE_PIN = (byte)0x23;
    private final byte INS_UNBLOCK_PIN = (byte) 0x24;
    private final byte INS_VERIFY_PIN = (byte) 0x25;
    private final byte INS_STORE = (byte)0x27;
    private final byte INS_LIST = (byte)0x28;
    private final byte INS_RETRIEVE = (byte)0x29;
    private final byte INS_UNPAIR = (byte)0x30;
    private final static byte INS_STATUS = (byte)0x31;

    //OTHER CLASSES
    public final Crypto crypto;
    public final UserInterface ui;

    //Data arrays
    private byte[] secret_IV; //array containing initialization secret and IV
    private byte[] challengeResponse;
    private byte[] pairingSecret;

    //Application State
    private boolean scOpened = false;
    private boolean pinVerified = false;
    private boolean pinBlocked = false;

    //CONSTANTS
    public static final byte STATUS_LEN = 6;

    public SecretStorageAPDU() {
        crypto = new Crypto();
        ui = new UserInterface(this);
        secret_IV = new byte[2*crypto.SC_SECRET_LENGTH];
        pairingSecret = new byte[crypto.SC_SECRET_LENGTH];
        challengeResponse = new byte[crypto.SC_SECRET_LENGTH];
    }

    public boolean checkPrerequisites(boolean scRequired, boolean pinRequired,
                                       boolean pinIsBlocked, boolean pinIsNotBlocked) {
        if (scRequired && !scOpened) {
            System.out.println("Operation not permitted! (SC not opened)");
            return false;
        }
        if (pinRequired && (!pinVerified || pinBlocked)) {
            System.out.println("Operation not permitted! (PIN not verified or blocked)");
            return false;
        }
        if (pinIsNotBlocked && pinBlocked) {
            System.out.println("Operation not permitted! (PIN is locked)");
            return false;
        }
        if (pinIsBlocked && !pinBlocked) {
            System.out.println("Operation not permitted! (PIN is not locked)");
            return false;
        }
        return true;
    }

    public boolean showStatus() {
        if (!checkPrerequisites(true, false, false, false)) {
            return false;
        }
        byte[] request = new byte[0];
        ResponseAPDU response = secureRespond(request, (short) request.length, INS_STATUS,
                (byte)0x00, (byte)0x00);
        byte[] data = response.getData();
        short len = verifyAndDecrypt(data);
        if(len != STATUS_LEN) {
            System.err.println("Invalid response length");
            return false;
        }
        System.out.println("Current status of JavaCard");
        System.out.printf("Pin validated: %b%n", data[0] == 0x01);
        System.out.printf("Pin remaining tries: %d%n", data[1]);
        System.out.printf("Puk remaining tries: %d%n", data[2]);
        System.out.printf("Opened secure channel: %b%n", data[3] == 0x01);
        System.out.printf("Phase 1 verified: %b%n", data[4] == 0x01);
        System.out.printf("Verified: %b%n", data[5] == 0x01);
        return true;
    }

    public boolean unpair(){
        if (!checkPrerequisites(true, true, false, true)) {
            return false;
        }
        System.out.println("Confirm operation UNPAIR by providing correct PIN");
        byte[] pin = ui.getPin(false);
        ResponseAPDU response = secureRespond(pin, (short) pin.length, INS_UNPAIR,
                (byte)0x00, (byte)0x00);
        if (response.getSW1() == 0x63) {
            pinVerified = false;
            System.err.printf("Provided incorrect PIN, need to sign again with %x attempts!%n",
                    response.getSW2() - 0xc0);
            return false;
        }
        if (response.getSW1() != 0x90) {
            System.err.println("Unpairing cannot be performed!");
            return false;
        }
        return true;
    }

    public boolean changePin(byte P1) {
        if (!checkPrerequisites(true, true, false, true)) {
            return false;
        }
        ResponseAPDU response;
        switch (P1) {
            case CHANGE_PIN:
                System.out.println("Enter new PIN");
                byte[] pin = ui.getPin(false);
                response = secureRespond(pin, (short) pin.length, INS_CHANGE_PIN,
                        CHANGE_PIN, (byte)0x00);
                break;
            case CHANGE_PUK:
                System.out.println("Enter new PUK");
                byte[] puk = ui.getPuk(false);
                response = secureRespond(puk, (short) puk.length, INS_CHANGE_PIN,
                        CHANGE_PUK, (byte)0x00);
                break;
            case CHANGE_PAIRING_SECRET:
                byte[] ps = new byte[crypto.SC_SECRET_LENGTH + crypto.PIN_LENGTH];
                crypto.genBytes(ps, crypto.PIN_LENGTH, crypto.SC_SECRET_LENGTH);
                System.out.println("Confirm operation CHANGE_PAIRING_SECRET by providing correct PIN");
                pin = ui.getPin(false);
                System.arraycopy(pin, 0, ps, 0, crypto.PIN_LENGTH);
                response = secureRespond(ps, (short) ps.length, INS_CHANGE_PIN,
                        CHANGE_PAIRING_SECRET, (byte)0x00);
                if (response.getSW1() == 0x63) {
                    System.err.printf("Provided incorrect PIN, need to sign again with %x attempts!%n",
                            response.getSW2() - 0xc0);
                    pinVerified = false;
                }
                if (response.getSW1() == 0x90) {
                    crypto.sha256.doFinal(ps, crypto.PIN_LENGTH, crypto.SC_SECRET_LENGTH,
                            pairingSecret, (short) 0);
                    System.out.println("New pairing secret:");
                    System.out.println(Arrays.toString(pairingSecret));
                    reset();
                }
                break;
            default:
                System.err.println("Invalid operation");
                return false;
        }
        if (response.getSW1() != 0x90) {
            System.err.println("Command failed!");
            return false;
        }
        return true;
    }

    public boolean unblockPin() {
        if (!checkPrerequisites(true, false, true, false)) {
            return false;
        }
        byte[] request;
        ResponseAPDU response;
        int attemptsRemaining;
        do{
            byte[] puk = ui.getPuk(false);
            System.out.println("Enter new PIN:");
            byte[] pin = ui.getPin(false);
            request = Arrays.copyOf(puk,  puk.length + pin.length);;
            System.arraycopy(pin, 0, request, puk.length, pin.length);
            response = secureRespond(request, (short) request.length, INS_UNBLOCK_PIN,
                    (byte)0x00, (byte)0x00);
            if (response.getSW1() != 0x90) {
                attemptsRemaining = response.getSW2() - 0xc0;
                if (attemptsRemaining <= 0) {
                    System.out.println("Card blocked permanently!");
                    return false;
                }
                System.out.printf("Invalid PUK, remains %x attempts%n", attemptsRemaining);
            }
        } while (response.getSW1() != 0x90);
        System.out.println("PIN changed");
        pinVerified = true;
        pinBlocked = false;
        return true;
    }

    public boolean verifyPin() {
        if (!checkPrerequisites(true, false, false, true)) {
            return false;
        }
        ResponseAPDU response;
        int attemptsRemaining;
        do{
            byte[] pin = ui.getPin(false);
            response = secureRespond(pin, (short) pin.length, INS_VERIFY_PIN,
                    (byte)0x00, (byte)0x00);
            if (response.getSW1() != 0x90) {
                attemptsRemaining = response.getSW2() - 0xc0;
                if (attemptsRemaining <= 0) {
                    pinBlocked = true;
                    System.out.println("Card blocked, use PUK to unblock!");
                    return false;
                }
                System.out.printf("Invalid PIN, remains %x attempts%n", attemptsRemaining);
            }
        } while (response.getSW1() != 0x90);
        pinVerified = true;
        System.out.println("PIN verified!");
        return true;
    }

    public boolean verifySc() {
        byte[] challenge = new byte[crypto.SC_SECRET_LENGTH];
        crypto.random.nextBytes(challenge);
        System.arraycopy(challenge, 0, challengeResponse, 0, crypto.SC_SECRET_LENGTH);
        ResponseAPDU response = secureRespond(challenge, (short) challenge.length, INS_VERIFY_KEYS,
                (byte)0x00, (byte)0x00);
        byte[] responseData = response.getData();
        int length = verifyAndDecrypt(responseData);
        if (length != crypto.SC_SECRET_LENGTH) {
            reset();
            return false;
        }
        CommandAPDU commandAPDU = new CommandAPDU(0x00, INS_VERIFY_KEYS, 0x01, 0x00, responseData,
                (short) 0, length);
        response = Run.simulator.transmitCommand(commandAPDU);
        if (!Arrays.equals(response.getData(), challenge)) {
            reset();
            return false;
        }
        return true;
    }

    //USE THIS TO RESPOND BY SECURE CHANNEL
    public ResponseAPDU secureRespond(byte[] input, short len, byte instruction, byte P1, byte P2) {
        short cipher_len = (short) (((len + 1) / crypto.AES_BLOCK_SIZE + 1) * crypto.AES_BLOCK_SIZE);
        byte[] request = new byte[ISO7816.OFFSET_CDATA + crypto.AES_BLOCK_SIZE + cipher_len];
        crypto.aes.init(crypto.scEncKey, Cipher.MODE_ENCRYPT, secret_IV, (short) 0, crypto.SC_BLOCK_SIZE);
        len = crypto.aes.doFinal(input, (short) 0, len, request, (short) (ISO7816.OFFSET_CDATA + crypto.SC_BLOCK_SIZE));
        request[0] = CLA_SIMPLE_APPLET;
        request[1] = instruction;
        request[2] = P1;
        request[3] = P2;
        request[4] = (byte) (len + crypto.AES_BLOCK_SIZE);
        computeMAC(request, len);
        Util.arrayCopyNonAtomic(request, ISO7816.OFFSET_CDATA, secret_IV, (short) 0, crypto.SC_BLOCK_SIZE);
        CommandAPDU commandAPDU = new CommandAPDU(request, (short) 0, request.length);
        return Run.simulator.transmitCommand(commandAPDU);
    }

    public short computeMAC(byte[] buffer, short len) {
        crypto.mac.init(crypto.scMacKey, Signature.MODE_SIGN);
        crypto.mac.update(buffer, (short) 0, ISO7816.OFFSET_CDATA);
        crypto.mac.update(secret_IV, crypto.SC_BLOCK_SIZE, (short) (crypto.SC_BLOCK_SIZE - ISO7816.OFFSET_CDATA)); // zero padding
        return crypto.mac.sign(buffer, (short) (ISO7816.OFFSET_CDATA + crypto.SC_BLOCK_SIZE), len,
                buffer, ISO7816.OFFSET_CDATA);
    }

    //USE THIS TO RECEIVE DATA FROM SECURE CHANNEL
    public short verifyAndDecrypt(byte[] buffer) {
        short apduLen = (short) buffer.length;
        if (!verifyMAC(buffer, apduLen)) {
            reset();
            throw new RuntimeException();
        }
        crypto.aes.init(crypto.scEncKey, Cipher.MODE_DECRYPT, secret_IV, (short) 0, crypto.SC_BLOCK_SIZE);
        Util.arrayCopy(buffer, (short) 0, secret_IV, (short) 0, crypto.SC_BLOCK_SIZE);
        return crypto.aes.doFinal(buffer, crypto.SC_BLOCK_SIZE,
                (short) (apduLen - crypto.SC_BLOCK_SIZE) , buffer, (short) 0);
    }

    public boolean verifyMAC(byte[] buffer, short len) {
        crypto.mac.init(crypto.scMacKey, Signature.MODE_VERIFY);
        return crypto.mac.verify(buffer, crypto.AES_BLOCK_SIZE, (short) (len - crypto.AES_BLOCK_SIZE),
                buffer, (short) 0, crypto.AES_BLOCK_SIZE);
    }

    public void openSc() {
        byte[] request_data = new byte[EC_KEY_LEN];
        crypto.scKeypair.genKeyPair();
        crypto.ecdh.init(crypto.scKeypair.getPrivate());
        ECPublicKey pk = (ECPublicKey) crypto.scKeypair.getPublic();
        short length = pk.getW(request_data, (short) 0);
        if (length != EC_KEY_LEN) {
            throw new RuntimeException("Keys are different length");
        }
        CommandAPDU commandAPDU = new CommandAPDU(0x00, INS_OPEN_SC, 0x00, 0x00, request_data);
        ResponseAPDU responseAPDU = Run.simulator.transmitCommand(commandAPDU);
        byte[] response = responseAPDU.getData();
        try {
            length = crypto.ecdh.generateSecret(response, (short) (crypto.AES_BLOCK_SIZE + crypto.SC_SECRET_LENGTH),
                    EC_KEY_LEN, secret_IV, (short) 0);
        } catch (Exception e){
            throw new RuntimeException();
        }
        crypto.sha512.update(secret_IV, (short) 0, length);
        crypto.sha512.update(pairingSecret, (short) 0, crypto.SC_SECRET_LENGTH);
        crypto.sha512.doFinal(response, (short) 0, crypto.SC_SECRET_LENGTH, secret_IV, (short) 0);
        crypto.scEncKey.setKey(secret_IV, (short) 0);
        crypto.scMacKey.setKey(secret_IV, crypto.SC_SECRET_LENGTH);
        System.arraycopy(response, crypto.SC_SECRET_LENGTH, secret_IV, (short) 0, crypto.SC_BLOCK_SIZE);
        Util.arrayFillNonAtomic(secret_IV, crypto.SC_BLOCK_SIZE,
                (short) (2*crypto.SC_SECRET_LENGTH - crypto.SC_BLOCK_SIZE), (byte) 0); // fill zero
        scOpened = true;
    }

    public void selectApp() {
        reset();
        byte[] select_response = Run.simulator.selectAppletWithResult(Run.appletAID);
        switch (select_response[0]){
            case RET_NOT_INIT:
                System.out.println("Card not initialized, starting first time setup...\n");
                initialize(select_response);
                return;
            case RET_INITIALIZED:
                System.out.println("Card already initialized, starting...\n");
                return;
            default:
                throw new RuntimeException();
        }
    }
    public ResponseAPDU initialize(byte[] response) {
        byte[] data_to_encrypt = new byte[crypto.INIT_ENC_LEN];
        crypto.ecdh.init(crypto.scKeypair.getPrivate());
        short pk_len = (short) (response.length - 3);
        try {
            crypto.ecdh.generateSecret(response, (short) 1, pk_len, secret_IV, (short) 0);
        } catch (Exception e) {
            System.out.println("Invalid PK received");
            return null;
        }
        ECPublicKey pk = (ECPublicKey) crypto.scKeypair.getPublic();
        byte[] request_data = new byte[pk_len + crypto.AES_BLOCK_SIZE + crypto.INIT_AES_LEN];
        short mpk_len = pk.getW(request_data, (short) 0);
        if (mpk_len != pk_len) {
            throw new RuntimeException("Keys are different length");
        }
        System.arraycopy(ui.getPin(false), 0, data_to_encrypt, 0, crypto.PIN_LENGTH);
        System.arraycopy(ui.getPuk(false), 0, data_to_encrypt, crypto.PIN_LENGTH, crypto.PUK_LENGTH);
        crypto.genBytes(data_to_encrypt, (short) (crypto.PIN_LENGTH + crypto.PUK_LENGTH), crypto.SC_SECRET_LENGTH);
        crypto.sha256.doFinal(data_to_encrypt, (short) (crypto.PIN_LENGTH + crypto.PUK_LENGTH), crypto.SC_SECRET_LENGTH,
                pairingSecret, (short) 0);
        crypto.genBytes(request_data, pk_len, crypto.AES_BLOCK_SIZE);
        crypto.scEncKey.setKey(secret_IV, (short) 0);
        crypto.aes.init(crypto.scEncKey, Cipher.MODE_ENCRYPT, request_data, pk_len, crypto.AES_BLOCK_SIZE);
        crypto.aes.doFinal(data_to_encrypt, (short) 0, crypto.INIT_ENC_LEN, request_data,
                (short) (pk_len + crypto.AES_BLOCK_SIZE));
        CommandAPDU commandAPDU = new CommandAPDU(0x00, INS_INIT, 0x00, 0x00, request_data);
        return Run.simulator.transmitCommand(commandAPDU);
    }

    public char getState() {
        if (pinBlocked) {
            return '!';
        }
        if (pinVerified) {
            return 'V';
        }
        return 'X';
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
