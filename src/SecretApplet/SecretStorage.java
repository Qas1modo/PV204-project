package SecretApplet;

import javacard.framework.*;
import javacard.security.*;

public class SecretStorage extends Applet {

    //CONSTANTS
    private final short MAX_SECRET_NAME_LENGTH = 32;
    private final short MAX_SECRET_VALUE_LENGTH = 128;

    //PIN and OTHER OBJECTS
    private OwnerPIN pin;
    private OwnerPIN puk;
    private final Crypto crypto;

    //PIN CONSTANTS
    static final byte PIN_LENGTH = 6;
    static final byte PUK_LENGTH = 12;
    static final byte PIN_RETRIES = 3;
    static final byte PUK_RETRIES = 10;

    final byte CHANGE_PIN = 0;
    final byte CHANGE_PUK = 1;
    final byte CHANGE_PAIRING_SECRET = 2;

    // MAIN INSTRUCTION CLASS
    final byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // INSTRUCTIONS

    private final static byte INS_INIT = (byte) 0x20;
    private final static byte INS_OPEN_SC = (byte)0x21;
    private final static byte INS_VERIFY_KEYS = (byte) 0x22;
    private final static byte INS_CHANGE_PIN = (byte)0x23;
    private final static byte INS_UNBLOCK_PIN = (byte) 0x24;
    private final static byte INS_VERIFY_PIN = (byte) 0x25;
    private final static byte INS_STORE = (byte)0x27;
    private final static byte INS_LIST = (byte)0x28;
    private final static byte INS_RETRIEVE = (byte)0x29;
    private final static byte INS_CHANGE_SECRET = (byte)0x45;
    private final static byte INS_PIN_CHANGE = (byte) 0x46;

    // EXCEPTIONS
    final static short SW_Exception = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException = (short) 0xff03;
    final static short SW_ArrayStoreException = (short) 0xff04;
    final static short SW_NullPointerException = (short) 0xff05;
    final static short SW_NegativeArraySizeException = (short) 0xff06;
    final static short SW_CryptoException_prefix = (short) 0xf100;
    final static short SW_SystemException_prefix = (short) 0xf200;
    final static short SW_PINException_prefix = (short) 0xf300;
    final static short SW_TransactionException_prefix = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix = (short) 0xf500;

    // SECURE CHANNEL
    private SecureChannel secureChannel;
    private byte[] secretName;
    private byte[] secretValue;

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new SecretStorage(bArray, bOffset, bLength);
    }

    protected SecretStorage(byte[] buffer, short offset, byte length) {
        crypto = new Crypto();
        secretName = new byte[MAX_SECRET_NAME_LENGTH];
        secretValue = new byte[MAX_SECRET_VALUE_LENGTH];
        register();
    }

    public boolean select() {
        return clearSession();
    }

    public void deselect() {
        clearSession();
    }

    private boolean clearSession(){
        pin.reset();
        puk.reset();
        if (secureChannel != null) {
            secureChannel.reset();
        }
        return true;
    }

    public void process(APDU apdu) throws ISOException {
        if (pin == null) {
            if (secureChannel == null) {
                secureChannel= new SecureChannel(crypto);
            }
            init(apdu);
            return;
        }
        if (selectingApplet()) {
            reselect(apdu);
            return;
        }
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        try {
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_OPEN_SC:
                        secureChannel.openSC(apdu);
                        break;
                    case INS_VERIFY_KEYS:
                        secureChannel.verifyKeys(apdu);
                        break;
                    case INS_CHANGE_PIN:
                        changePIN(apduBuffer);
                        break;
                    case INS_UNBLOCK_PIN:
                        unblockPIN(apduBuffer);
                        break;
                    case INS_VERIFY_PIN:
                        verifyPIN(apduBuffer);
                        break;
                    case INS_STORE:
                        storeData(apduBuffer);
                        break;
                    case INS_LIST:
                        listNames(apdu);
                        break;
                    case INS_RETRIEVE:
                        showSecret(apdu);
                        break;
                    // remove in release - safe mechanism
                    case INS_CHANGE_SECRET:
                        secureChannel.updatePairingSecret(apduBuffer, ISO7816.OFFSET_CDATA);
                        break;
                    case INS_PIN_CHANGE:
                        changeUserPIN(apduBuffer, PIN_LENGTH);
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            }
            else {
                throw new ISOException(ISO7816.SW_CLA_NOT_SUPPORTED);
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

    private void init (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        if (selectingApplet()) {
            short len = (byte) secureChannel.copyPublicKey(apduBuffer, (short) 0);
            apdu.setOutgoingAndSend((short) 0, len);
            return;
        }
        if (apduBuffer[ISO7816.OFFSET_INS] == INS_INIT) {
            secureChannel.decryptInit(apduBuffer);
            byte length = (byte) (PIN_LENGTH + PUK_LENGTH + secureChannel.SC_SECRET_LENGTH);
            if (apduBuffer[ISO7816.OFFSET_LC] != length) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            pin = new OwnerPIN(PIN_RETRIES, PIN_LENGTH);
            pin.update(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);
            puk = new OwnerPIN(PUK_RETRIES, PUK_LENGTH);
            puk.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH), PUK_LENGTH);
            secureChannel.initSC(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH + PUK_LENGTH));
            return;
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    public void reselect(APDU apdu) {
        pin.reset();
        puk.reset();
        secureChannel.reset();
        byte[] apduBuffer = apdu.getBuffer();
        short keyLen = secureChannel.copyPublicKey(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, keyLen);
    }

    private void verifyPIN(byte[] apduBuffer) {
        byte len = (byte) secureChannel.processAPDU(apduBuffer);
        if (len != PIN_LENGTH || !allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len)) {
            ISOException.throwIt((short)((short) 0x63c0 | (short) pin.getTriesRemaining()));
        }
    }

    private void unblockPIN(byte[] apduBuffer) {
        byte len = (byte) secureChannel.processAPDU(apduBuffer);
        if (pin.getTriesRemaining() != 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (len != (PUK_LENGTH + PIN_LENGTH) || !allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!puk.check(apduBuffer, ISO7816.OFFSET_CDATA, PUK_LENGTH)) {
            ISOException.throwIt((short)((short) 0x63c0 | (short) puk.getTriesRemaining()));
        }
        pin.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PUK_LENGTH), PIN_LENGTH);
        pin.check(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PUK_LENGTH), PIN_LENGTH);
        puk.reset();
    }

    private void changePIN(byte[] apduBuffer) {
        byte len = (byte) secureChannel.processAPDU(apduBuffer);
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case CHANGE_PIN:
                changeUserPIN(apduBuffer, len);
                break;
            case CHANGE_PUK:
                changePUK(apduBuffer, len);
                break;
            case CHANGE_PAIRING_SECRET:
                changePS(apduBuffer, len);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void changeUserPIN(byte[] apduBuffer, byte len) {
        if (!(len == PIN_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        pin.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
        pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len);
    }

    private void changePUK(byte[] apduBuffer, byte len) {
        if (!(len == PUK_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        puk.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
    }

    private void changePS(byte[] apduBuffer, byte len) {
        if (len != secureChannel.SC_SECRET_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        secureChannel.updatePairingSecret(apduBuffer, ISO7816.OFFSET_CDATA);
    }

    private boolean allDigits(byte[] buffer, short offset, short length) {
        while(length > 0) {
            length--;
            byte c = buffer[(short)(offset+length)];
            if (c < 0x30 || c > 0x39) {
                return false;
            }
        }
        return true;
    }


    private void storeData(byte[] buffer) {
        short secretNameLength = (short)(buffer[ISO7816.OFFSET_LC] & 0xff);
/*        if (secretNameLength > MAX_SECRET_NAME_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, secretName, (short)0, secretNameLength);
        short secretValueLength = (short)(buffer[ISO7816.OFFSET_CDATA + secretNameLength] & 0xff);
        if (secretValueLength > MAX_SECRET_VALUE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA + secretNameLength + 1),
                secretValue, (short)0, secretValueLength);*/
    }

    private void listNames(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
/*        short le = apdu.setOutgoing();
        short secretNameLength = (short)(secretName.length & 0xff);
        buffer[0] = (byte)secretNameLength;
        Util.arrayCopy(secretName, (short)0, buffer, (short)1, secretNameLength);
        apdu.setOutgoingLength((short)(secretNameLength + 1));
        apdu.sendBytes((short)0, (short)(secretNameLength + 1));*/
    }

    private void showSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
/*        short secretNameLength = (short)(buffer[ISO7816.OFFSET_LC] & 0xff);
        if (secretNameLength > MAX_SECRET_NAME_LENGTH) {
            throw new ISOException(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, secretName, (short)0, secretNameLength);
        if (pin.isValidated()) {
            short secretValueLength = (short)(secretValue.length & 0xff);
            Util.arrayCopy(secretValue, (short)0, buffer, (short)0, secretValueLength);
            apdu.setOutgoingAndSend((short)0, secretValueLength);
        } else {
            throw new ISOException(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }*/
    }
}