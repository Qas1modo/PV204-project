package main;

public class Const {
    public static final byte MAX_SECRET_LENGTH = 64;
    public static final byte MAX_NAME_LENGTH = 16;
    public static final byte SUCCESS = 0x01;
    public static final byte FAILURE = 0x02;

    //INSTRUCTIONS
    public final static byte CLA_SIMPLE_APPLET = (byte) 0x00;
    public final static byte INS_INIT = (byte) 0x20;
    public final static byte INS_OPEN_SC = (byte)0x21;
    public final static byte INS_VERIFY_KEYS = (byte) 0x22;
    public final static byte INS_CHANGE_PIN = (byte)0x23;
    public final static byte INS_UNBLOCK_PIN = (byte) 0x24;
    public final static byte INS_VERIFY_PIN = (byte) 0x25;
    public final static byte INS_STORE = (byte)0x27;
    public final static byte INS_LIST = (byte)0x28;
    public final static byte INS_RETRIEVE = (byte)0x29;
    public final static byte INS_UNPAIR = (byte)0x30;
    public final static byte INS_STATUS = (byte)0x31;
    public final static byte INS_REMOVE = (byte)0x32;

    //SPECIFIC COMMANDS (P1)
    public final static byte CHANGE_PIN = 0;
    public final static byte CHANGE_PUK = 1;
    public final static byte CHANGE_PAIRING_SECRET = 2;

    //CONSTANTS
    public final static byte EC_KEY_LEN = 65;
    public static final byte STATUS_LEN = 8;

    //RETURN VALUES
    public final static byte RET_NOT_INIT = (byte) 0xa0;
    public final static byte RET_INITIALIZED = (byte) 0xa1;

    //PIN CONSTANTS
    public final static byte PIN_LENGTH = 6;
    public final static byte PUK_LENGTH = 10;

    //CRYPTO CONSTANTS
    public final static short AES_BLOCK_SIZE = 16;
    public final static short SC_KEY_LENGTH = 256;
    public final static short SC_SECRET_LENGTH = 32;
    public final static short SC_BLOCK_SIZE = 16;
    public final static short INIT_ENC_LEN = PIN_LENGTH + PUK_LENGTH + SC_SECRET_LENGTH;
    public final static short INIT_AES_LEN = (INIT_ENC_LEN / SC_BLOCK_SIZE + 1) * SC_BLOCK_SIZE;

    // UI constants
    public final static int COMMAND_MAX_LEN = 3;

    public final static short SW_STORAGE_FULL = (short) 0x6A84;

    public final static short SW_VALUE_ALREADY_PRESENT = (short) 0x6A85;
}
