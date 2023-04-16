package applet;

import javacard.framework.*;
import javacard.security.*;

public class SecretStorageApplet extends Applet {
    //PIN and OTHER OBJECTS
    private final OwnerPIN pin;
    private final OwnerPIN puk;
    private final SecureChannel sc;

    public static final byte PIN_LENGTH = 6;
    public static final byte PUK_LENGTH = 10;
    public static final byte PIN_RETRIES = 3;
    public static final byte PUK_RETRIES = 10;
    public static final byte STATUS_LEN = 8;
    public static final byte CHANGE_PIN = 0x00;
    public static final byte CHANGE_PUK = 0x01;
    public static final byte CHANGE_PAIRING_SECRET = 0x02;

    public static final byte MAX_SECRETS = 30;
    public static final byte MAX_SECRET_LENGTH = 64;
    public static final byte MAX_NAME_LENGTH = 16;
    public static final byte MAX_NAMES_PER_RESPONSE = 14;
    public static final byte SUCCESS = 0x01;

    public static final byte NAME_STORAGE = MAX_NAME_LENGTH + 1;
    public static final byte SECRET_STORAGE = MAX_SECRET_LENGTH + 1;

    // MAIN INSTRUCTION CLASS
    private static final byte CLA_SIMPLE_APPLET = (byte) 0x00;

    //RESPONSE STATUS
    private static final byte RET_NOT_INIT = (byte) 0xa0;
    private final static byte RET_INITIALIZED = (byte) 0xa1;

    private boolean initialized;

    // INSTRUCTIONS

    private final static byte INS_INIT = (byte) 0x20;
    private final static byte INS_OPEN_SC = (byte) 0x21;
    private final static byte INS_VERIFY_KEYS = (byte) 0x22;
    private final static byte INS_CHANGE_PIN = (byte) 0x23;
    private final static byte INS_UNBLOCK_PIN = (byte) 0x24;
    private final static byte INS_VERIFY_PIN = (byte) 0x25;
    private final static byte INS_STORE = (byte) 0x27;
    private final static byte INS_LIST = (byte) 0x28;
    private final static byte INS_RETRIEVE = (byte) 0x29;
    private final static byte INS_UNPAIR = (byte) 0x30;
    private final static byte INS_STATUS = (byte) 0x31;
    private final static byte INS_REMOVE = (byte) 0x32;

    // EXCEPTIONS
    private final static short SW_Exception = (short) 0xff01;
    private final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    private final static short SW_ArithmeticException = (short) 0xff03;
    private final static short SW_ArrayStoreException = (short) 0xff04;
    private final static short SW_NullPointerException = (short) 0xff05;
    private final static short SW_NegativeArraySizeException = (short) 0xff06;
    private final static short SW_CryptoException_prefix = (short) 0xf100;
    private final static short SW_SystemException_prefix = (short) 0xf200;
    private final static short SW_PINException_prefix = (short) 0xf300;
    private final static short SW_TransactionException_prefix = (short) 0xf400;
    private final static short SW_CardRuntimeException_prefix = (short) 0xf500;
    private final static short SW_STORAGE_FULL = (short) 0x6A84;
    private final static short SW_VALUE_ALREADY_PRESENT = (short) 0x6A85;
    private final static short SW_INVALID_PASSWORD = (short) 0x63c0;

    private final byte[] secretNames;
    private final byte[] secretValues;

    private byte secretCount;


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SecretStorageApplet();
    }

    public SecretStorageApplet() {
        sc = new SecureChannel();
        secretNames = new byte[(short) (MAX_SECRETS * NAME_STORAGE)];
        secretValues = new byte[(short) (MAX_SECRETS * SECRET_STORAGE)];
        secretCount = 0;
        initialized = false;
        pin = new OwnerPIN(PIN_RETRIES, PIN_LENGTH);
        puk = new OwnerPIN(PUK_RETRIES, PUK_LENGTH);
        register();
    }

    public void process(APDU apdu) {
        if (!initialized) {
            init(apdu);
            return;
        }
        if (selectingApplet()) {
            reselect(apdu);
            return;
        }
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        try {
            if (buffer[ISO7816.OFFSET_CLA] == CLA_SIMPLE_APPLET) {
                switch (buffer[ISO7816.OFFSET_INS]) {
                    case INS_OPEN_SC:
                        sc.openSC(apdu, buffer);
                        break;
                    case INS_VERIFY_KEYS:
                        sc.verifyKeys(apdu, buffer);
                        break;
                    case INS_CHANGE_PIN:
                        changePIN(apdu, buffer);
                        break;
                    case INS_UNBLOCK_PIN:
                        unblockPIN(apdu, buffer);
                        break;
                    case INS_VERIFY_PIN:
                        verifyPIN(apdu, buffer);
                        break;
                    case INS_STORE:
                        storeSecret(apdu, buffer);
                        break;
                    case INS_LIST:
                        listNames(apdu, buffer);
                        break;
                    case INS_RETRIEVE:
                        showSecret(apdu, buffer);
                        break;
                    case INS_REMOVE:
                        removeSecret(apdu, buffer);
                        break;
                    case INS_UNPAIR:
                        unpair(buffer);
                        break;
                    case INS_STATUS:
                        status(apdu, buffer);
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e;
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
    }

    private void init(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        if (selectingApplet()) {
            apduBuffer[0] = RET_NOT_INIT;
            short len = (short) (sc.copyPublicKey(apduBuffer, (short) 1) + 1);
            apdu.setOutgoingAndSend((short) 0, len);
            return;
        }
        if (apduBuffer[ISO7816.OFFSET_INS] == INS_INIT) {
            sc.decryptInit(apduBuffer);
            if (apduBuffer[ISO7816.OFFSET_LC] != SecureChannel.INIT_ENC_LEN) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            pin.update(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);
            puk.update(apduBuffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH), PUK_LENGTH);
            sc.initSC(apduBuffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH + PUK_LENGTH));
            initialized = true;
            return;
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    public void reselect(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        pin.reset();
        puk.reset();
        sc.reset();
        buffer[0] = RET_INITIALIZED;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    public void storeSecret(APDU apdu, byte[] buffer) {
        short len = sc.processAPDU(buffer);
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (secretCount >= MAX_SECRETS) {
            ISOException.throwIt(SW_STORAGE_FULL);
        }
        short nameLength = buffer[ISO7816.OFFSET_CDATA];
        short secretLength = buffer[(short) (ISO7816.OFFSET_CDATA + nameLength + 1)];
        if (len > MAX_SECRET_LENGTH + MAX_NAME_LENGTH + 2 ||
                nameLength > MAX_NAME_LENGTH ||
                secretLength > MAX_SECRET_LENGTH ||
                nameLength == 0 || secretLength == 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short index = findSecretIndex(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_CDATA] + 1));
        if (index != -1) {
            ISOException.throwIt(SW_VALUE_ALREADY_PRESENT);
        }
        short storeIndex = findFirstEmpty();
        JCSystem.beginTransaction();
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, secretNames,
                (short) (storeIndex * NAME_STORAGE), (short) (nameLength + 1));
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + nameLength + 1),
                secretValues, (short) (storeIndex * SECRET_STORAGE), (short) (secretLength + 1));
        secretCount++;
        JCSystem.commitTransaction();
        buffer[0] = SUCCESS;
        sc.secureRespond(apdu, buffer, (short) 1);
    }

    public void listNames(APDU apdu, byte[] buffer) {
        short len = sc.processAPDU(buffer);
        if (len > 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte responseTimes = (byte) ((byte) (secretCount - 1) / MAX_NAMES_PER_RESPONSE);
        if (buffer[ISO7816.OFFSET_P1] > responseTimes) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short responseIndex = buffer[ISO7816.OFFSET_P1];
        short offset = 1;
        byte empty = 0;
        for (short i = 0; i < MAX_NAMES_PER_RESPONSE &&
                (short) (responseIndex * MAX_NAMES_PER_RESPONSE + i) < (short) (secretCount + empty); i++) {
            short currentIndex = (short) ((short) ((short) (responseIndex * MAX_NAMES_PER_RESPONSE) + i) * NAME_STORAGE);
            if (secretNames[currentIndex] == 0x00) {
                empty++;
                continue;
            }
            Util.arrayCopy(secretNames, currentIndex, buffer, offset, (short) (secretNames[currentIndex] + 1));
            offset += secretNames[currentIndex] + 1;
        }
        buffer[0] = responseTimes;
        sc.secureRespond(apdu, buffer, offset);
    }

    public void showSecret(APDU apdu, byte[] buffer) {
        short index = (short) (findSecretByName(buffer) * SECRET_STORAGE);
        Util.arrayCopy(secretValues, (short) (index + 1), buffer, (short) 0, secretValues[index]);
        sc.secureRespond(apdu, buffer, secretValues[index]);
    }

    public void removeSecret(APDU apdu, byte[] buffer) {
        short index = findSecretByName(buffer);
        JCSystem.beginTransaction();
        Util.arrayFillNonAtomic(secretNames, (short) (index * NAME_STORAGE), NAME_STORAGE, (byte) 0x00);
        Util.arrayFillNonAtomic(secretValues, (short) (index * SECRET_STORAGE), SECRET_STORAGE, (byte) 0x00);
        secretCount--;
        JCSystem.commitTransaction();
        buffer[0] = SUCCESS;
        sc.secureRespond(apdu, buffer, (short) 1);
    }

    public void verifyPIN(APDU apdu, byte[] buffer) {
        short len = sc.processAPDU(buffer);
        if (len != PIN_LENGTH || !allDigits(buffer, ISO7816.OFFSET_CDATA, len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) len)) {
            ISOException.throwIt((short) (SW_INVALID_PASSWORD + pin.getTriesRemaining()));
        }
        buffer[0] = SUCCESS;
        sc.secureRespond(apdu, buffer, (short) 1);
    }

    public void unblockPIN(APDU apdu, byte[] buffer) {
        byte len = (byte) sc.processAPDU(buffer);
        if (pin.getTriesRemaining() != 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (len != (PUK_LENGTH + PIN_LENGTH) || !allDigits(buffer, ISO7816.OFFSET_CDATA, len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        if (!puk.check(buffer, ISO7816.OFFSET_CDATA, PUK_LENGTH)) {
            if (puk.getTriesRemaining() == 0) {
                removeSensitiveData();
            }
            JCSystem.commitTransaction();
            ISOException.throwIt((short) (SW_INVALID_PASSWORD + puk.getTriesRemaining()));
        }
        JCSystem.commitTransaction();
        pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + PUK_LENGTH), PIN_LENGTH);
        pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + PUK_LENGTH), PIN_LENGTH);
        puk.reset();
        buffer[0] = SUCCESS;
        sc.secureRespond(apdu, buffer, (short) 1);
    }

    public void status(APDU apdu, byte[] buffer) {
        if (sc.isOpen()) {
            sc.processAPDU(buffer);
        }
        buffer[0] = pin.isValidated() ? (byte) 0x01 : (byte) 0x02;
        buffer[1] = pin.getTriesRemaining();
        buffer[2] = puk.getTriesRemaining();
        buffer[3] = sc.isOpen() ? (byte) 0x01 : (byte) 0x02;
        buffer[4] = sc.firstPhaseCompleted ? (byte) 0x01 : (byte) 0x02;
        buffer[5] = sc.authenticated ? (byte) 0x01 : (byte) 0x02;
        buffer[6] = secretCount;
        buffer[7] = MAX_SECRETS;
        if (sc.isOpen()){
            sc.secureRespond(apdu, buffer, STATUS_LEN);
        } else {
            apdu.setOutgoingAndSend((short) 0, STATUS_LEN);
        }
    }

    public void unpair(byte[] buffer) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short len = sc.processAPDU(buffer);
        if (len != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
            ISOException.throwIt((short) (SW_INVALID_PASSWORD + pin.getTriesRemaining()));
        }
        JCSystem.beginTransaction();
        removeSensitiveData();
        sc.removePairingSecret();
        initialized = false;
        sc.reset();
        JCSystem.commitTransaction();
    }

    public void changePIN(APDU apdu, byte[] buffer) {
        short len = sc.processAPDU(buffer);
        boolean result = false;
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        switch (buffer[ISO7816.OFFSET_P1]) {
            case CHANGE_PIN:
                result = changeUserPIN(buffer, len);
                break;
            case CHANGE_PUK:
                result = changePUK(buffer, len);
                break;
            case CHANGE_PAIRING_SECRET:
                result = changePS(buffer, len);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (result) {
            buffer[0] = SUCCESS;
        }
        sc.secureRespond(apdu, buffer, (short) 1);
        if (buffer[ISO7816.OFFSET_P1] == CHANGE_PAIRING_SECRET) {
            sc.reset();
        }
    }

    private boolean changeUserPIN(byte[] buffer, short len) {
        if (!(len == 2 * PIN_LENGTH && allDigits(buffer, ISO7816.OFFSET_CDATA, len))) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
            ISOException.throwIt((short) (SW_INVALID_PASSWORD + pin.getTriesRemaining()));
        }
        pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH), PIN_LENGTH);
        return pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH), PIN_LENGTH);
    }


    private boolean changePUK(byte[] buffer, short len) {
        if (!(len == (PUK_LENGTH + PIN_LENGTH) && allDigits(buffer, ISO7816.OFFSET_CDATA, len))) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
            ISOException.throwIt((short) (SW_INVALID_PASSWORD + pin.getTriesRemaining()));
        }
        puk.update(buffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH), PUK_LENGTH);
        return true;
    }

    private boolean changePS(byte[] buffer, short len) {
        if (len != SecureChannel.SC_SECRET_LENGTH + PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
            ISOException.throwIt((short) (SW_INVALID_PASSWORD + pin.getTriesRemaining()));
        }
        sc.updatePairingSecret(buffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH));
        return true;
    }

    private short findFirstEmpty() {
        for (short i = 0; i < secretCount; i++) {
            if (secretNames[(short) (i * NAME_STORAGE)] == 0x00) {
                return i;
            }
        }
        return secretCount;
    }

    private void removeSensitiveData() {
        Util.arrayFillNonAtomic(secretNames, (short) 0, (short) (MAX_SECRETS * NAME_STORAGE), (byte) 0x00);
        Util.arrayFillNonAtomic(secretValues, (short) 0, (short) (MAX_SECRETS * SECRET_STORAGE), (byte) 0x00);
        secretCount = 0;
    }

    private short findSecretByName(byte[] buffer) {
        short len = sc.processAPDU(buffer);
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (len > MAX_NAME_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short index = findSecretIndex(buffer, ISO7816.OFFSET_CDATA, len);
        if (index == -1) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        return index;
    }

    private boolean allDigits(byte[] buffer, short offset, short length) {
        while (length > 0) {
            length--;
            byte c = buffer[(short) (offset + length)];
            if (c < 0x30 || c > 0x39) {
                return false;
            }
        }
        return true;
    }

    private short findSecretIndex(byte[] name, short offset, short length) {
        for (short i = 0; i < secretCount; i++) {
            if (Util.arrayCompare(name, offset, secretNames, (short) (i * NAME_STORAGE), length) == 0) {
                return i;
            }
        }
        return -1;
    }
}
