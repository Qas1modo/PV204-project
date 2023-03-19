package main;

public class UserInterface {

    private final int COMMAND_MAX_LEN = 3;
    SecretStorageAPDU apdu;
    Crypto crypto;
    public UserInterface(SecretStorageAPDU apdu) {
        this.crypto = apdu.crypto;
        this.apdu = apdu;
    }

    public void start() {
        boolean secureChannelOpened;
        while (true)
        {
            apdu.selectApp();
            do{
                try {
                    apdu.openSc();
                } catch (Exception e) {
                    System.out.println("Failed to open secure channel, exiting...");
                    return;
                }
                secureChannelOpened = apdu.verifySc();
                if (!secureChannelOpened) {
                    System.out.println("Failed to verify secure channel, retrying...");
                }
            } while (!secureChannelOpened);
            parseInput();
        }
    }

    public void parseInput() {
        while (true) {
            System.out.printf("Command number (1 to show available commands)[%c]:", apdu.getState());
            byte[] command = readLine(COMMAND_MAX_LEN);
            if (!allDigits(command, command.length)) {
                System.out.println("Invalid input, only digits are allowed");
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
                    if (command.length == 1 && command[0] == 48) {
                        System.out.println("Exiting...");
                        System.exit(0);
                    }
                }
                break;
            } catch (NumberFormatException e){
                System.err.println("Not a number!");
            }
        }
        System.out.println("Secure channel destroyed, proceeding to reinitialization!");
    }

    //Add new methods here to call APDU operations
    private boolean callCommand(int input) throws NeedResetException {
        switch (input) {
            case 1:
                showLegend();
                return true;
            case 2:
                return apdu.verifyPin();
            case 3:
                return apdu.unblockPin();
            case 4:
                return apdu.changePin(apdu.CHANGE_PIN);
            case 5:
                return apdu.changePin(apdu.CHANGE_PUK);
            case 6:
                if (!apdu.changePin(apdu.CHANGE_PAIRING_SECRET)) {
                    return false;
                }
                throw new NeedResetException();
            case 7:
                if (!apdu.unpair()) {
                    return false;
                }
                throw new NeedResetException(true);
            case 8:
                return apdu.showStatus();
            case 20:
                apdu.reset();
                throw new NeedResetException();
            case 21:
                System.exit(0);
            default:
                System.err.println("Invalid command!");
                return false;
        }
    }

    private void showLegend() {
        System.out.println("Type 1 to show this menu!");
        System.out.println("Type 2 to verify PIN!");
        System.out.println("Type 3 to unblock PIN!");
        System.out.println("Type 4 to change PIN!");
        System.out.println("Type 5 to change PUK!");
        System.out.println("Type 6 to change pairing secret (RESETS SC)!");
        System.out.println("Type 7 to remove pairing secret (RESETS SC)!");
        System.out.println("Type 8 to show status!");
        System.out.println("Type 20 to RESET SC!");
        System.out.println("Type 21 to exit!");
    }


    public byte[] getPin(boolean ret_stat) {
        if (ret_stat) {
            return new byte[]{0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
        }
        System.out.print("Enter PIN:");
        byte[] pin = readLine(crypto.PIN_LENGTH);
        while (pin == null || pin.length != crypto.PIN_LENGTH || !allDigits(pin, pin.length)) {
            System.out.printf("PIN must be %s digits long%n", crypto.PIN_LENGTH);
            System.out.print("Enter PIN:");
            pin = readLine(crypto.PIN_LENGTH);
        }
        return pin;
    }

    public byte[] getPuk(boolean ret_stat) {
        if (ret_stat) {
            return new byte[]{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
        }
        System.out.print("Enter PUK:");
        byte[] puk = readLine(crypto.PUK_LENGTH);
        while (puk == null || puk.length != crypto.PUK_LENGTH || !allDigits(puk, puk.length)) {
            System.out.printf("PUK must be %s digits long%n", crypto.PUK_LENGTH);
            System.out.print("Enter PUK:");
            puk = readLine(crypto.PUK_LENGTH);
        }
        return puk;
    }

    public byte[] readLine(int maxLen) {
        int index = 0;
        byte readChar;
        byte[] data = new byte[maxLen];
        try {
            do{
                readChar = (byte) System.in.read();
                if (index < maxLen) {
                    if (readChar == '\n') {
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
        }
        if (index > maxLen + 1) {
            return null;
        }
        return data;
    }

    public boolean allDigits(byte[] buffer, int length) {
        while (length > 0) {
            length--;
            byte c = buffer[length];
            if (c < 0x30 || c > 0x39) {
                return false;
            }
        }
        return true;
    }
}
