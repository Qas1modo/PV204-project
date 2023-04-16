package main;

import java.io.*;
import java.security.DigestException;
import java.util.Arrays;
import java.util.Base64;

public class UserInterface {
    private final SecretStorageAPDU apdu;
    private final SecureChannel sc;
    private static final String FILENAME = "secret.txt";
    public UserInterface(SecretStorageAPDU apdu) {
        this.apdu = apdu;
        this.sc = apdu.sc;
    }

    public void start() {
        boolean secureChannelOpened;
        apdu.selectApp(true);
        while (true)
        {
            try {
                sc.openSc();
            } catch (DigestException e) {
                System.out.println("Failed to open secure channel, exiting...");
                return;
            }
            secureChannelOpened = sc.verifySc();
            if (!secureChannelOpened) {
                System.out.println("Failed to verify secure channel, exiting...");
                return;
            }
            if (!parseInput()) {
                return;
            }
        }
    }

    public boolean parseInput() {
        while (true) {
            System.out.printf("Command ([help] to show available commands)[%c]:", sc.getState());
            byte[] command = readLine(Const.COMMAND_MAX_LEN);
            if (command == null) {
                System.out.println("Invalid or too long input!");
                continue;
            }
            try {
                callCommand(new String(command));
            } catch (NeedResetException e){
                if (e.pairingRemoved) {
                    System.out.print("Successfully unpaired, pair again ? (type n to exit):");
                    command = readLine(1);
                    if (command != null && command.length == 1 && command[0] == 110) {
                        System.out.println("Exiting...");
                        return false;
                    }
                }
                break;
            } catch (Exception e) {
                System.out.println("Command did not finish successfully!");
            }
        }
        System.out.println("Secure channel destroyed, proceeding to establishment!");
        apdu.selectApp(false);
        return true;
    }

    //Add new methods here to call APDU operations
    private boolean callCommand(String input) throws NeedResetException {
        switch (input) {
            case "exit":
                System.out.print("Confirm exit by typing y:");
                byte[] confirm = readLine(1);
                if (confirm == null || confirm.length != 1 || confirm[0] != 121) {
                    System.out.println("Cancelling exit...");
                    return true;
                }
                System.exit(0);
            case "help":
                return showLegend();
            case "verify":
                return apdu.verifyPin();
            case "status":
                return apdu.showStatus();
            case "list":
                return apdu.listNames();
            case "store":
                return apdu.storeSecret();
            case "show":
                return apdu.showSecret(false);
            case "bytes":
                return apdu.showSecret(true);
            case "remove":
                return apdu.removeSecret();
            case "unblock":
                return apdu.unblockPin();
            case "newPIN":
                return apdu.changePin(Const.CHANGE_PIN);
            case "newPUK":
                return apdu.changePin(Const.CHANGE_PUK);
            case "newPS":
                if (!apdu.changePin(Const.CHANGE_PAIRING_SECRET)) {
                    return false;
                }
                throw new NeedResetException();
            case "unpair":
                if (!apdu.unpair()) {
                    return false;
                }
                throw new NeedResetException(true);
            case "reset":
                sc.reset();
                throw new NeedResetException();
            default:
                System.out.println("Invalid command!");
                return false;
        }
    }

    private boolean showLegend() {
        System.out.println("[exit] to stop the program");
        System.out.println("[help] to show this menu");
        System.out.println("[status] to get current state of the card");
        System.out.println("[reset] to reset SC");
        System.out.println("[list] to list secrets");
        if (sc.isPermanentlyBlocked()) {
            System.out.println("Card is blocked, other commands unavailable");
        } else if (sc.isPinBlocked()) {
            System.out.println("[unblock] to unblock PIN");
        } else if (!sc.isPinVerified()) {
            System.out.println("[verify] to verify PIN");
        } else {
            System.out.println("[store] to save secret to the card.");
            System.out.println("[show] writes specific secret in UTF8 format");
            System.out.println("[bytes] writes specific secret in byte array format");
            System.out.println("[remove] to delete secret from the card");
            System.out.println("[newPIN] to change PIN");
            System.out.println("[newPUK] to change PUK");
            System.out.println("[newPS] to change pairing secret (resets SC)");
            System.out.println("[unpair] to remove pairing secret from the card (resets SC)");
        }
        return true;
    }

    public static byte[] getPin() {
        System.out.print("Enter PIN:");
        byte[] pin = readLine(Const.PIN_LENGTH);
        while (pin == null || pin.length != Const.PIN_LENGTH || !allDigits(pin, pin.length)) {
            System.out.printf("PIN must be %s digits long%n", Const.PIN_LENGTH);
            System.out.print("Enter PIN:");
            pin = readLine(Const.PIN_LENGTH);
        }
        return pin;
    }

    public static byte[] getPuk() {
        System.out.print("Enter PUK:");
        byte[] puk = readLine(Const.PUK_LENGTH);
        while (puk == null || puk.length != Const.PUK_LENGTH || !allDigits(puk, puk.length)) {
            System.out.printf("PUK must be %s digits long%n", Const.PUK_LENGTH);
            System.out.print("Enter PUK:");
            puk = readLine(Const.PUK_LENGTH);
        }
        return puk;
    }

    public static byte[] readLine(int maxLen) {
        int index = 0;
        byte readChar;
        byte[] data = new byte[maxLen];
        try {
            do{
                readChar = (byte) System.in.read();
                if (index < maxLen) {
                    if (readChar == '\n') {
                        if (index == 0) {
                            return null;
                        }
                        byte[] smallerData = new byte[index];
                        System.arraycopy(data, 0, smallerData, 0, index);
                        return smallerData;
                    }
                    data[index] = readChar;
                }
                index++;
            } while (readChar != '\n');
        }
        catch (Exception e) {
            System.err.println("Unable to get input!");
            return null;
        }
        if (index > maxLen + 1) {
            return null;
        }
        return data;
    }

    public static boolean allDigits(byte[] buffer, int length) {
        while (length > 0) {
            length--;
            byte c = buffer[length];
            if (c < 0x30 || c > 0x39) {
                return false;
            }
        }
        return true;
    }

    public static String outputPS(byte[] buffer, int off, int len) {
         String output = Base64.getEncoder().encodeToString(Arrays.copyOfRange(buffer, off, off+len));
         if (Run.inSimulator) {
             return output;
         }
         File file = new File(FILENAME);
         try {
             if (!file.exists() && !file.createNewFile()) {
                 System.err.println("Failed to create file to save PS!");
                 return output;
             }
             BufferedWriter writer = new BufferedWriter(new FileWriter(FILENAME));
             writer.write(output);
             writer.newLine();
             writer.close();
         } catch (Exception e) {
             System.err.println("Unable to save PS into filesystem.");
             return output;
         }
         return output;
    }

    public static byte[] inputPS() {
        byte[] ps = new byte[Const.SC_SECRET_LENGTH];
        String input;
        try {
            BufferedReader reader = new BufferedReader(new FileReader(FILENAME));
            input = reader.readLine();
            reader.close();
        } catch (IOException e) {
            System.out.println("Unable to retrieve PS from file!");
            System.out.print("Input PS manually:");
            input = Arrays.toString(readLine(Const.PS_LEN));
        }
        if (input.length() != Const.PS_LEN) {
            throw new RuntimeException("Invalid PS length!");
        }
        byte[] base = Base64.getDecoder().decode(input);
        System.arraycopy(base, 0, ps, 0, Const.SC_SECRET_LENGTH);
        return ps;
    }
}
