package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class Key_Value extends Applet {
    // Applet-specific status words
    private static final short SW_PIN_VERIFICATION_REQUIRED = (short) 0x6300;
    private static final short SW_PIN_CHANGE_REQUIRED = (short) 0x6301;
    private static final short SW_SECRET_NOT_FOUND = (short) 0x6A88;
    private static final short SW_NAME_TOO_LONG = (short) 0x6A80;
    private static final short SW_VALUE_TOO_LONG = (short) 0x6A81;
    private static final short SW_STORAGE_FULL = (short) 0x6A84;
    private static final short SW_INVALID_P1_P2 = (short) 0x6B00;

    // PIN-related constants
    private static final byte MAX_PIN_TRIES = 3;
    private static final byte PIN_SIZE = 6;
    private OwnerPIN pin;

    // Name-value pair related constants
    private static final short MAX_SECRET_NAME_LENGTH = 32;
    private static final short MAX_SECRET_VALUE_LENGTH = 64;
    private static final short MAX_SECRET_COUNT = 16;
    private short secretCount;
    private byte[][] secretNames;
    private byte[][] secretValues;

    // Encryption-related constants
    //private static final byte[] ENCRYPTION_KEY = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    //private static final byte[] ENCRYPTION_IV = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    private Cipher encryptionCipher;
    private Cipher decryptionCipher;

    // APDU-related constants
    private static final byte CLA_SECRET_STORE = (byte) 0xB0;
    private static final byte INS_SET_SECRET = (byte) 0x00;
    private static final byte INS_GET_SECRET_VALUE = (byte) 0x01;
    private static final byte INS_LIST_SECRET_NAMES = (byte) 0x02;
    private static final byte INS_VERIFY_PIN = (byte) 0x03;
    private static final byte INS_CHANGE_PIN = (byte) 0x04;

    // Constructor
    public Key_Value() {
        // Initialize the PIN
        pin = new OwnerPIN(MAX_PIN_TRIES, PIN_SIZE);
        pin.update(new byte[]{0x01, 0x02, 0x03, 0x04}, (short) 0, PIN_SIZE);

        // Initialize the name-value pair arrays
        secretCount = 0;
        secretNames = new byte[MAX_SECRET_COUNT][MAX_SECRET_NAME_LENGTH];
        secretValues = new byte[MAX_SECRET_COUNT][MAX_SECRET_VALUE_LENGTH];

        // Create AES key object
        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        // Generate a random 128-bit key
        Crypto crypto = new Crypto();
        byte[] keyBytes = new byte[key.getSize()];
        key.getKey(keyBytes, (short) 0);
        crypto.random.generateData(keyBytes, (short) 0, (short) keyBytes.length);

        // Generate a random 64-bit initialization vector (IV)
        byte[] iv = new byte[8];
        crypto.random.generateData(iv, (short) 0, (short) iv.length);

        // Initialize the encryption/decryption ciphers
        Cipher encryptionCipher = crypto.aes;
        encryptionCipher.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);

        Cipher decryptionCipher = crypto.aes;
        decryptionCipher.init(key, Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
    }

    // Install the applet
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Key_Value().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    // Process an incoming APDU command
    public void process(APDU apdu) {
        // Get the buffer to use
        byte[] buffer = apdu.getBuffer();

        // Check the class byte
        if (buffer[ISO7816.OFFSET_CLA] != CLA_SECRET_STORE) {
            ISOException.throwIt(SW_INVALID_P1_P2);
        }

        // Check the PIN
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        // Determine the instruction byte and perform the corresponding action
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_SET_SECRET:
                storeSecret(apdu, buffer, CLA_SECRET_STORE, buffer[ISO7816.OFFSET_P1]);
                break;

            case INS_GET_SECRET_VALUE:
                getSecretValue(apdu, buffer, CLA_SECRET_STORE, buffer[ISO7816.OFFSET_P1]);
                break;

            case INS_LIST_SECRET_NAMES:
                listSecretNames(apdu, buffer, CLA_SECRET_STORE);
                break;

            case INS_VERIFY_PIN:
                verifyPIN(apdu, buffer);
                break;

            case INS_CHANGE_PIN:
                changePIN(apdu, buffer);
                break;

            default:
                ISOException.throwIt(SW_INVALID_P1_P2);
        }
    }

    // Method to store a secret
    private void storeSecret(APDU apdu, byte[] buffer, byte cla, byte p1) {
        // Check the P1 parameter
        if (p1 != 0) {
            ISOException.throwIt(SW_INVALID_P1_P2);
        }

        // Get the name and value from the APDU buffer
        short nameLength = buffer[ISO7816.OFFSET_LC];
        if (nameLength > MAX_SECRET_NAME_LENGTH) {
            ISOException.throwIt(SW_NAME_TOO_LONG);
        }
        apdu.setIncomingAndReceive();
        short valueLength = (short) (apdu.getIncomingLength() - nameLength);
        if (valueLength > MAX_SECRET_VALUE_LENGTH) {
            ISOException.throwIt(SW_VALUE_TOO_LONG);
        }
        byte[] name = new byte[nameLength];
        byte[] value = new byte[valueLength];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, name, (short) 0, nameLength);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + nameLength), value, (short) 0, valueLength);

        // Check if the secret already exists
        short index = findSecretIndex(name, (short) 0, nameLength);
        if (index != -1) {
            ISOException.throwIt(SW_INVALID_P1_P2);
        }

        // Check if there's room for a new secret
        if (secretCount >= MAX_SECRET_COUNT) {
            ISOException.throwIt(SW_STORAGE_FULL);
        }

        // Encrypt the value
        byte[] encryptedValue = new byte[MAX_SECRET_VALUE_LENGTH];
        short encryptedLength = encrypt(value, (short) 0, valueLength, encryptedValue, (short) 0);

        // Add the new secret
        Util.arrayCopy(name, (short) 0, secretNames[secretCount], (short) 0, nameLength);
        Util.arrayCopy(encryptedValue, (short) 0, secretValues[secretCount], (short) 0, encryptedLength);
        secretCount++;
    }
    public short encrypt(byte[] plaintext, short plaintextOffset, short plaintextLength, byte[] ciphertext, short ciphertextOffset) {
        return encryptionCipher.doFinal(plaintext, plaintextOffset, plaintextLength, ciphertext, ciphertextOffset);
    }

    public short decrypt(byte[] ciphertext, short ciphertextOffset, short ciphertextLength, byte[] plaintext, short plaintextOffset) {
        return decryptionCipher.doFinal(ciphertext, ciphertextOffset, ciphertextLength, plaintext, plaintextOffset);
    }





    // Method to get the value of a secret
    private void getSecretValue(APDU apdu, byte[] buffer, byte cla, byte p1) {
        // Check the P1 parameter
        if (p1 != 0) {
            ISOException.throwIt(SW_INVALID_P1_P2);
        }

        // Get the name from the APDU buffer
        short nameLength = buffer[ISO7816.OFFSET_LC];
        if (nameLength > MAX_SECRET_NAME_LENGTH) {
            ISOException.throwIt(SW_NAME_TOO_LONG);
        }
        apdu.setIncomingAndReceive();
        byte[] name = new byte[nameLength];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, name, (short) 0, nameLength);

        // Find the secret
        short index = findSecretIndex(name, (short) 0, nameLength);
        if (index == -1) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);;
        }

        // Decrypt the value
        byte[] encryptedValue = secretValues[index];
        short encryptedLength = (short) encryptedValue.length;
        byte[] decryptedValue = new byte[MAX_SECRET_VALUE_LENGTH];
        short decryptedLength = decrypt(encryptedValue, (short) 0, encryptedLength, decryptedValue, (short) 0);


        // Send the value back to the APDU buffer
        apdu.setOutgoing();
        apdu.setOutgoingLength(decryptedLength);
        Util.arrayCopy(decryptedValue, (short) 0, buffer, (short) 0, decryptedLength);
        apdu.sendBytes((short) 0, decryptedLength);
    }

    // Method to list the names of all stored secrets
    private void listSecretNames(APDU apdu, byte[] buffer, byte cla) {
        // Check that no P1 or P2 parameter is specified
        if (buffer[ISO7816.OFFSET_P1] != 0 || buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(SW_INVALID_P1_P2);
        }

        // Check that the APDU buffer is large enough to hold all the secret names
        short totalLength = (short) (secretCount * (MAX_SECRET_NAME_LENGTH + 1));
        if (totalLength > apdu.setOutgoing()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Copy the secret names to the APDU buffer
        byte[] outgoingBuffer = apdu.getBuffer();
        short outgoingOffset = 0;
        for (short i = 0; i < secretCount; i++) {
            byte[] name = secretNames[i];
            short nameLength = (short) name.length;
            Util.arrayCopy(name, (short) 0, outgoingBuffer, outgoingOffset, nameLength);
            outgoingOffset += nameLength;
            outgoingBuffer[outgoingOffset++] = 0x00;
        }
        apdu.setOutgoingLength(totalLength);
        apdu.sendBytes((short) 0, totalLength);
    }

    // Method to verify the PIN
    private void verifyPIN(APDU apdu, byte[] buffer) {
        // Get the PIN from the APDU buffer
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        if (pinLength != PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();
        byte[] pinValue = new byte[PIN_SIZE];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pinValue, (short) 0, PIN_SIZE);

        // Verify the PIN
        boolean isValid = pin.check(pinValue, (short) 0, PIN_SIZE);
        if (!isValid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    // Method to change the PIN
    private void changePIN(APDU apdu, byte[] buffer) {
        // Get the old and new PINs from the APDU buffer
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        if (pinLength != 2 * PIN_SIZE) {
            ISOException.throwIt((short) 0x6984);
        }
        apdu.setIncomingAndReceive();
        byte[] oldPINValue = new byte[PIN_SIZE];
        byte[] newPINValue = new byte[PIN_SIZE];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, oldPINValue, (short) 0, PIN_SIZE);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + PIN_SIZE), newPINValue, (short) 0, PIN_SIZE);

        // Verify the old PIN
        boolean isValid = pin.check(oldPINValue, (short) 0, PIN_SIZE);
        if (!isValid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Change the PIN
        pin.update(newPINValue, (short) 0, PIN_SIZE);
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
