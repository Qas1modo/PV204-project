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
            do{
                try {
                    sc.openSc();
                } catch (DigestException e) {
                    System.out.println("Failed to open secure channel, exiting...");
                    return;
                }
                secureChannelOpened = sc.verifySc();
                if (!secureChannelOpened) {
                    System.out.println("Failed to verify secure channel, retrying...");
                }
            } while (!secureChannelOpened);
            if (!parseInput()) {
                return;
            }
        }
    }

    public boolean parseInput() {
        while (true) {
            System.out.printf("Command number (1 to show available commands)[%c]:", sc.getState());
            byte[] command = readLine(Const.COMMAND_MAX_LEN);
            if (command == null || !allDigits(command, command.length)) {
                System.out.println("Invalid input, only numbers between 0 and 999 are allowed");
                continue;
            }
            try {
                if (!callCommand(Integer.parseInt(new String(command)))) {
                    System.out.println("Command did not finish successfully");
                }
            } catch (NeedResetException e){
                if (e.pairingRemoved) {
                    System.out.print("Successfully unpaired, pair again ? (type 0 to exit):");
                    command = readLine(1);
                    if (command != null && command.length == 1 && command[0] == 48) {
                        System.out.println("Exiting...");
                        return false;
                    }
                }
                break;
            } catch (NumberFormatException e){
                System.err.println("Not a number!");
            }
        }
        System.out.println("Secure channel destroyed, proceeding to reinitialization!");
        apdu.selectApp(false);
        return true;
    }

    //Add new methods here to call APDU operations
    private boolean callCommand(int input) throws NeedResetException {
        switch (input) {
            case 0:
                System.out.print("Confirm exit by typing y:");
                byte[] confirm = readLine(1);
                if (confirm == null || confirm.length != 1 || confirm[0] != 121) {
                    System.out.print("Cancelling exit...");
                    return true;
                }
                System.exit(0);
            case 1:
                showLegend();
                return true;
            case 2:
                return apdu.verifyPin();
            case 3:
                return apdu.showStatus();
            case 4:
                return apdu.storeSecret(false);
            case 5:
                return apdu.listNames();
            case 6:
                return apdu.showSecret(false);
            case 7:
                return apdu.showSecret(true);
            case 8:
                return apdu.removeSecret();
            case 9:
                return apdu.unblockPin();
            case 10:
                return apdu.changePin(Const.CHANGE_PIN);
            case 11:
                return apdu.changePin(Const.CHANGE_PUK);
            case 12:
                if (!apdu.changePin(Const.CHANGE_PAIRING_SECRET)) {
                    return false;
                }
                throw new NeedResetException();
            case 13:
                if (!apdu.unpair()) {
                    return false;
                }
                throw new NeedResetException(true);
            case 14:
                sc.reset();
                throw new NeedResetException();
            case 15:
                return apdu.storeSecret(true);
            default:
                System.err.println("Invalid command!");
                return false;
        }
    }

    private void showLegend() {
        System.out.println("Type 0 to exit!");
        System.out.println("Type 1 to show this menu!");
        System.out.println("Type 2 to verify PIN!");
        System.out.println("Type 3 to show status!");
        System.out.println("Type 4 to store secret!");
        System.out.println("Type 5 to list secrets!");
        System.out.println("Type 6 to show specific secret in UTF8!");
        System.out.println("Type 7 to show specific secret in byte array!");
        System.out.println("Type 8 to remove secret!");
        System.out.println("Type 9 to unblock PIN!");
        System.out.println("Type 10 to change PIN!");
        System.out.println("Type 11 to change PUK!");
        System.out.println("Type 12 to change pairing secret (resets SC)!");
        System.out.println("Type 13 to remove pairing secret (resets SC)!");
        System.out.println("Type 14 to reset SC!");
        System.out.println("Type 15 to create random secret (for testing)!");
    }


    public static byte[] getPin(boolean ret_stat) {
        if (ret_stat) {
            return new byte[]{0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
        }
        System.out.print("Enter PIN:");
        byte[] pin = readLine(Const.PIN_LENGTH);
        while (pin == null || pin.length != Const.PIN_LENGTH || !allDigits(pin, pin.length)) {
            System.out.printf("PIN must be %s digits long%n", Const.PIN_LENGTH);
            System.out.print("Enter PIN:");
            pin = readLine(Const.PIN_LENGTH);
        }
        return pin;
    }

    public static byte[] getPuk(boolean ret_stat) {
        if (ret_stat) {
            return new byte[]{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
        }
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
            throw new RuntimeException("Unable to retrieve PS!");
        }
        byte[] base = Base64.getDecoder().decode(input);
        System.arraycopy(base, 0, ps, 0, Const.SC_SECRET_LENGTH);
        return ps;
    }
}
