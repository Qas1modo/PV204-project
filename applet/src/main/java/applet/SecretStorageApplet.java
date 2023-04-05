package applet;

import javacard.framework.*;
import javacard.security.*;

public class SecretStorageApplet extends Applet
{
	//PIN and OTHER OBJECTS
	private OwnerPIN pin;
	private OwnerPIN puk;
	private final SecureChannel secureChannel;

	public static final byte PIN_LENGTH = 6;
	public static final byte PUK_LENGTH = 10;
	public static final byte PIN_RETRIES = 3;
	public static final byte PUK_RETRIES = 10;
	public static final byte CHANGE_PIN = 0;
	public static final byte CHANGE_PUK = 1;
	public static final byte CHANGE_PAIRING_SECRET = 2;
	public static final byte STATUS_LEN = 8;

	public static final byte MAX_SECRETS = 20;
	public static final byte MAX_SECRET_LENGTH = 64;
	public static final byte MAX_NAME_LENGTH = 16;
	public static final byte MAX_NAMES_PER_RESPONSE = 14;
	public static final byte SUCCESS = 0x01;
	public static final byte FAILURE = 0x02;

	// MAIN INSTRUCTION CLASS
	private static final byte CLA_SIMPLE_APPLET = (byte) 0x00;

	//RESPONSE STATUS
	private static final byte RET_NOT_INIT = (byte) 0xa0;
	private final static byte RET_INITIALIZED = (byte) 0xa1;

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
	private final static byte INS_UNPAIR = (byte)0x30;
	private final static byte INS_STATUS = (byte)0x31;
	private final static byte INS_REMOVE = (byte)0x32;
	private final static byte INS_CHANGE_SECRET = (byte)0x45;
	private final static byte INS_PIN_CHANGE = (byte) 0x46;

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

	private final byte[][] secretNames;
	private final byte[][] secretValues;

	private short secretCount;


	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new SecretStorageApplet();
	}

	public SecretStorageApplet() {
		secureChannel = new SecureChannel();
		secretNames = new byte[MAX_SECRETS][MAX_NAME_LENGTH + 1];
		secretValues = new byte[MAX_SECRETS][MAX_SECRET_LENGTH + 1];
		secretCount = 0;
		register();
	}

	public void process(APDU apdu)
	{
		if (pin == null) {
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
			if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLE_APPLET) {
				switch (apduBuffer[ISO7816.OFFSET_INS]) {
					case INS_OPEN_SC:
						secureChannel.openSC(apdu);
						break;
					case INS_VERIFY_KEYS:
						secureChannel.verifyKeys(apdu);
						break;
					case INS_CHANGE_PIN:
						changePIN(apdu);
						break;
					case INS_UNBLOCK_PIN:
						unblockPIN(apdu);
						break;
					case INS_VERIFY_PIN:
						verifyPIN(apdu);
						break;
					case INS_STORE:
						storeSecret(apdu);
						break;
					case INS_LIST:
						listNames(apdu);
						break;
					case INS_RETRIEVE:
						showSecret(apdu);
						break;
					case INS_REMOVE:
						removeSecret(apdu);
						break;
					case INS_UNPAIR:
						unpair(apduBuffer);
						break;
					case INS_STATUS:
						status(apdu);
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
	private void init (APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		if (selectingApplet()) {
			apduBuffer[0] = RET_NOT_INIT;
			byte len = (byte) (secureChannel.copyPublicKey(apduBuffer, (short) 1) + 1);
			apdu.setOutgoingAndSend((short) 0, len);
			return;
		}
		if (apduBuffer[ISO7816.OFFSET_INS] == INS_INIT) {
			secureChannel.decryptInit(apduBuffer);
			if (apduBuffer[ISO7816.OFFSET_LC] != SecureChannel.INIT_ENC_LEN) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			pin = new OwnerPIN(PIN_RETRIES, PIN_LENGTH);
			puk = new OwnerPIN(PUK_RETRIES, PUK_LENGTH);
			pin.update(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);
			puk.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH), PUK_LENGTH);
			secureChannel.initSC(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH + PUK_LENGTH));
			return;
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	}

	public void storeSecret(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short len = secureChannel.processAPDU(buffer);
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		if (secretCount >= MAX_SECRETS) {
			ISOException.throwIt(SW_STORAGE_FULL);
		}
		short nameLength = buffer[ISO7816.OFFSET_CDATA];
		short secretLength = buffer[ISO7816.OFFSET_CDATA + nameLength + 1];
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
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, secretNames[storeIndex],
				(short) 0, (short) (nameLength + 1));
		Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + nameLength + 1),
				secretValues[storeIndex], (short) 0, (short) (secretLength + 1));
		secretCount++;
		buffer[0] = SUCCESS;
		secureChannel.secureRespond(apdu, buffer, (short) 1);
	}

	public void listNames(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short len = secureChannel.processAPDU(buffer);
		if(len > 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		byte responseTimes = (byte) ((secretCount - 1) / MAX_NAMES_PER_RESPONSE);
		if (buffer[ISO7816.OFFSET_P1] > responseTimes) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		short responseIndex = buffer[ISO7816.OFFSET_P1];
		short offset = 1;
		short empty = 0;
		for (short i = 0; i < MAX_NAMES_PER_RESPONSE &&
				(responseIndex*MAX_NAMES_PER_RESPONSE+i) < (secretCount + empty); i++) {
			byte[] nameToCopy = secretNames[(responseIndex*MAX_NAMES_PER_RESPONSE) + i];
			if (nameToCopy[0] == 0x00) {
				empty++;
				continue;
			}
			Util.arrayCopy(nameToCopy, (short) 0, buffer, offset, (short) (nameToCopy[0] + 1));
			offset += nameToCopy[0] + 1;
		}
		buffer[0] = responseTimes;
		secureChannel.secureRespond(apdu, buffer, offset);
	}

	public void showSecret(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short index = findSecretByName(buffer);
		Util.arrayCopy(secretValues[index], (short) 1, buffer, (short) 0, secretValues[index][0]);
		secureChannel.secureRespond(apdu, buffer, secretValues[index][0]);
	}

	public void removeSecret(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short index = findSecretByName(buffer);
		Util.arrayFillNonAtomic(secretNames[index], (short) 0, (short) (MAX_NAME_LENGTH + 1), (byte) 0x00);
		Util.arrayFillNonAtomic(secretValues[index], (short) 0, (short) (MAX_SECRET_LENGTH + 1), (byte) 0x00);
		secretCount--;
		buffer[0] = SUCCESS;
		secureChannel.secureRespond(apdu, buffer, (short) 1);
	}


	public void reselect(APDU apdu) {
		pin.reset();
		puk.reset();
		secureChannel.reset();
		byte[] apduBuffer = apdu.getBuffer();
		apduBuffer[0] = RET_INITIALIZED;
		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}

	public void verifyPIN(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte len = (byte) secureChannel.processAPDU(buffer);
		if (len != PIN_LENGTH || !allDigits(buffer, ISO7816.OFFSET_CDATA, len)) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if (!pin.check(buffer, ISO7816.OFFSET_CDATA, len)) {
			ISOException.throwIt((short)( 0x63c0 + pin.getTriesRemaining()));
		}
		buffer[0] = SUCCESS;
		secureChannel.secureRespond(apdu, buffer, (short) 1);
	}

	public void unblockPIN(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		byte len = (byte) secureChannel.processAPDU(apduBuffer);
		if (pin.getTriesRemaining() != 0) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		if (len != (PUK_LENGTH + PIN_LENGTH) || !allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len)) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if (!puk.check(apduBuffer, ISO7816.OFFSET_CDATA, PUK_LENGTH)) {
			ISOException.throwIt((short)( 0x63c0 + puk.getTriesRemaining()));
		}
		pin.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PUK_LENGTH), PIN_LENGTH);
		pin.check(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PUK_LENGTH), PIN_LENGTH);
		puk.reset();
		apduBuffer[0] = SUCCESS;
		secureChannel.secureRespond(apdu, apduBuffer, (short) 1);
	}

	public void status(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		secureChannel.processAPDU(apduBuffer);
		apduBuffer[0] = pin.isValidated() ? (byte) 0x01 : (byte) 0x02;
		apduBuffer[1] = pin.getTriesRemaining();
		apduBuffer[2] = puk.getTriesRemaining();
		apduBuffer[3] = secureChannel.isOpen() ? (byte) 0x01 : (byte) 0x02;
		apduBuffer[4] = secureChannel.firstPhaseCompleted ? (byte) 0x01 : (byte) 0x02;
		apduBuffer[5] = secureChannel.authenticated ? (byte) 0x01 : (byte) 0x02;
		apduBuffer[6] = (byte) secretCount;
		apduBuffer[7] = MAX_SECRETS;
		secureChannel.secureRespond(apdu, apduBuffer, STATUS_LEN);
	}

	public void unpair(byte[] apduBuffer){
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		byte len = (byte) secureChannel.processAPDU(apduBuffer);
		if (len != PIN_LENGTH) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)){
			ISOException.throwIt((short)( 0x63c0 + pin.getTriesRemaining()));
		}
		pin = null;
		puk = null;
		secureChannel.removePairingSecret();
		secureChannel.reset();
	}

	public void changePIN(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		byte len = (byte) secureChannel.processAPDU(apduBuffer);
		boolean result = false;
		if (!pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		switch (apduBuffer[ISO7816.OFFSET_P1]) {
			case CHANGE_PIN:
				result = changeUserPIN(apduBuffer, len);
				break;
			case CHANGE_PUK:
				result = changePUK(apduBuffer, len);
				break;
			case CHANGE_PAIRING_SECRET:
				result = changePS(apduBuffer, len);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if (result) {
			apduBuffer[0] = SUCCESS;
		}
		secureChannel.secureRespond(apdu, apduBuffer, (short) 1);
		if (apduBuffer[ISO7816.OFFSET_P1] == CHANGE_PAIRING_SECRET) {
			secureChannel.reset();
		}
	}

	private boolean changeUserPIN(byte[] apduBuffer, byte len) {
		if (!(len == 2*PIN_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
			ISOException.throwIt((short)( 0x63c0 + pin.getTriesRemaining()));
		}
		pin.update(apduBuffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH), PIN_LENGTH);
		return pin.check(apduBuffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH), PIN_LENGTH);
	}

	private boolean changePUK(byte[] apduBuffer, byte len) {
		if (!(len == (PUK_LENGTH + PIN_LENGTH) && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
			ISOException.throwIt((short)( 0x63c0 + pin.getTriesRemaining()));
		}
		puk.update(apduBuffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH), PUK_LENGTH);
		return true;
	}

	private boolean changePS(byte[] apduBuffer, byte len) {
		if (len != SecureChannel.SC_SECRET_LENGTH + PIN_LENGTH) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
			ISOException.throwIt((short)( 0x63c0 + pin.getTriesRemaining()));
		}
		secureChannel.updatePairingSecret(apduBuffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH));
		return true;
	}

	private short findFirstEmpty() {
		for (short i = 0; i < secretCount; i++) {
			if (secretNames[i][0] == 0x00) {
				return i;
			}
		}
		return secretCount;
	}

	private short findSecretByName(byte[] buffer) {
		short len = secureChannel.processAPDU(buffer);
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
		while(length > 0) {
			length--;
			byte c = buffer[(short)(offset+length)];
			if (c < 0x30 || c > 0x39) {
				return false;
			}
		}
		return true;
	}

	private short findSecretIndex(byte[] name, short offset, short length) {
		for (short i = 0; i < secretCount; i++) {
			if (Util.arrayCompare(name, offset, secretNames[i], (short) 0, length) == 0) {
				return i;
			}
		}
		return -1;
	}
}
