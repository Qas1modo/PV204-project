package applet;

import javacard.framework.*;
import javacard.security.*;

public class Key_Value {

    // Size of the key and secret value fields
    public static short SIZE_KEY = 48;
    public static short SIZE_VALUE = 64;

    private Key_Value next;  // Pointer to the next record in the linked list
    private static Key_Value first;  // Pointer to the first record in the linked list
    private static Key_Value deleted;  // Pointer to the first deleted record in the linked list

    private byte[] key;  // Byte array to store the key
    private byte keyLength;  // Length of the key
    private byte[] secretValue;  // Byte array to store the secret value
    private byte secretValueLength;  // Length of the secret value

    // Private constructor for creating a new record
    private Key_Value() {
        key = new byte[SIZE_KEY];
        secretValue = new byte[SIZE_VALUE];
        next = first;
        first = this;
    }

    // Method to get an instance of Key_Value, either by creating a new one or recycling a deleted one
    static Key_Value getInstance() {
        if (deleted == null) {
            // No element to recycle, create a new one
            return new Key_Value();
        } else {
            // Recycle the first available element
            Key_Value instance = deleted;
            deleted = instance.next;
            instance.next = first;
            first = instance;
            return instance;
        }
    }

    // Method to search for a record with a given key
    static Key_Value search(byte[] buf, short ofs, byte len) {
        for (Key_Value record = first; record != null; record = record.next) {
            if (record.keyLength != len) continue;
            if (Util.arrayCompare(record.key, (short) 0, buf, ofs, len) == 0)
                return record;
        }
        return null;
    }

    // Method to get the first record in the linked list
    public static Key_Value getFirst() {
        return first;
    }

    // Private method to remove a record from the linked list
    private void remove() {
        if (first == this) {
            first = next;
        } else {
            for (Key_Value record = first; record != null; record = record.next)
                if (record.next == this)
                    record.next = next;
        }
    }

    // Private method to recycle a record
    private void recycle() {
        RandomData m_secureRandom =  RandomData.getInstance(RandomData.ALG_FAST);

        // Set a seed for the random data generator
        m_secureRandom.setSeed(new byte[]{(byte)0x13,(byte)0x51,(byte)0x50,(byte)0x55,(byte)0x80,(byte)0x65,(byte)0x42,(byte)0x51,(byte)0x12,(byte)0x95},(short) 0,(short) 10);

        // Generate random data for the key and secret value fields
        m_secureRandom.generateData(this.key, (short) 0, (short) keyLength);
        m_secureRandom.generateData(this.secretValue, (short) 0, (short) secretValueLength);

        // Reset the record's key and secret value lengths, and add it to the list of deleted records
        next = deleted;
        keyLength = 0;
        secretValueLength = 0;
        deleted = this;
    }

    // Method to delete all records in the linked list
static void deleteAll() {
    // Loop through each record and delete it
    for (Key_Value record = first; record != null; record = record.next) {
        JCSystem.beginTransaction(); // Start transaction
        record.remove(); // Remove the record from memory
        record.recycle(); // Recycle the record to free up memory
        JCSystem.commitTransaction(); // Commit the transaction
    }
}

static byte delete(byte[] buf, short ofs, byte len) {
    // Find the record with the given key and delete it
    Key_Value keyManager = search(buf, ofs, len);
    if (keyManager != null) {
        JCSystem.beginTransaction(); // Start transaction
        keyManager.remove(); // Remove the record from memory
        keyManager.recycle(); // Recycle the record to free up memory
        JCSystem.commitTransaction(); // Commit the transaction

        return 1; // delete successful
    }

    return 0; // delete unsuccessful
}

static short getAllKeys(byte[] buf, byte ofs) {
    short len = 0;

    // Loop through each record and copy its key to the output buffer
    for (Key_Value record = first; record != null; record = record.next) {
        Util.arrayCopy(record.key, (short) 0, buf, ofs, record.keyLength);
        ofs += record.keyLength ;
        len += record.keyLength;
    }

    return len; // Return the total length of all keys
}

static short getAllKeyLens(byte[] buf, byte ofs) {
    short len = 0;

    // Loop through each record and copy its key length to the output buffer
    for (Key_Value record = first; record != null; record = record.next) {
        buf[ofs++] = record.keyLength;
        len++;
    }

    return len; // Return the total number of keys
}

byte getKey(byte[] buf, short ofs) {
    // Copy the key of this record to the output buffer
    Util.arrayCopy(key, (short) 0, buf, ofs, keyLength);
    return keyLength; // Return the length of the key
}

public byte getKeyLength() {
    return keyLength; // Return the length of the key
}

public Key_Value getNext() {
    return next; // Return the next record in the list
}

public void setKey(byte[] buf, short ofs, byte len) {
    // Copy the new key to this record's key field
    Util.arrayCopy(buf, ofs, key, (short) 0, len);
    keyLength = len; // Update the length of the key
}

byte getSecretValue(byte[] buf, short ofs) {
    // Copy the secret value of this record to the output buffer
    Util.arrayCopy(secretValue, (short) 0, buf, ofs, secretValueLength);
    return secretValueLength; // Return the length of the secret value
}

public byte getSecretValueLength() {
    return secretValueLength; // Return the length of the secret value
}

public void setSecretValue(byte[] buf, short ofs, byte len) {
    // Copy the new secret value to this record's secretValue field
    Util.arrayCopy(buf, ofs, secretValue, (short) 0, len);
    secretValueLength = len; // Update the length of the secret value
}
