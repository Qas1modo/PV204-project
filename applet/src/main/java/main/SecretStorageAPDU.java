package main;

import javacard.framework.ISO7816;

import javax.smartcardio.ResponseAPDU;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SecretStorageAPDU {
    public final SecureChannel sc;
    public SecretStorageAPDU() {
        sc = new SecureChannel();
    }

    private boolean checkPrerequisites(boolean scRequired, boolean pinRequired,
                                       boolean pinIsBlocked, boolean pinIsNotBlocked) {
        if (scRequired && !sc.isOpened()) {
            System.out.println("Operation not permitted! (SC not opened)");
            return false;
        }
        if (pinRequired && (!sc.isPinVerified() || sc.isPinBlocked())) {
            System.out.println("Operation not permitted! (PIN not verified or blocked)");
            return false;
        }
        if (pinIsNotBlocked && sc.isPinBlocked()) {
            System.out.println("Operation not permitted! (PIN is locked)");
            return false;
        }
        if (pinIsBlocked && !sc.isPinBlocked()) {
            System.out.println("Operation not permitted! (PIN is not locked)");
            return false;
        }
        return true;
    }

    private void confirmation(String operation, byte[] buffer, int offset) {
        System.out.printf("Confirm operation %s by providing correct PIN%n", operation);
        byte[] pin = UserInterface.getPin(false);
        System.arraycopy(pin, 0, buffer, offset, Const.PIN_LENGTH);
    }

    private boolean validPin(ResponseAPDU response) {
        if ((short) response.getSW() == ISO7816.SW_NO_ERROR) {
            byte[] data = response.getData();
            int len = sc.verifyAndDecrypt(data);
            if (len == 1 && data[0] == 0x01) {
                sc.pinVerified(true);
                return true;
            }
        }
        if (response.getSW1() == 0x63) {
            int attemptsRemaining = response.getSW2() - 0xc0;
            if (attemptsRemaining <= 0) {
                sc.pinBlocked(true);
                System.out.println("Card blocked, use PUK to unblock!");
                return false;
            }
            System.out.printf("Provided incorrect PIN, remains %x attempts!%n",
                    attemptsRemaining);
        }
        sc.pinVerified(false);
        return false;
    }

    private byte[] getInput(String prompt, int len){
        byte[] result;
        while (true) {
            System.out.print(prompt);
            result = UserInterface.readLine(len);
            if (result != null) {
                break;
            }
            System.out.println("Input invalid or too long, try again!");
        }
        return result;
    }

    private byte[] sendSecretName(byte instruction) {
        if (!checkPrerequisites(true, true, false, true)) {
            return null;
        }
        byte[] request = new byte[Const.MAX_NAME_LENGTH + 1];
        byte[] secretName;
        if (instruction == Const.INS_REMOVE) {
            secretName = getInput("Name of the secret to remove:", Const.MAX_NAME_LENGTH);
        }
        else {
            secretName = getInput("Name of the secret to show:", Const.MAX_NAME_LENGTH);
        }
        request[0] = (byte) secretName.length;
        System.arraycopy(secretName, 0, request, 1, secretName.length);
        ResponseAPDU response = sc.secureRespond(request, secretName.length + 1,
                instruction, (byte) 0, (byte) 0);
        short sw = (short) response.getSW();
        if (sw == ISO7816.SW_RECORD_NOT_FOUND) {
            System.out.println("Record not present on the card!");
            return null;
        }
        if (sw != ISO7816.SW_NO_ERROR) {
            if (instruction == Const.INS_REMOVE) {
                System.out.println("Record cannot be removed!");
            } else {
                System.out.println("Record cannot be retrieved!");
            }
            return null;
        }
        return response.getData();
    }


    public boolean showSecret(boolean inBytes) {
        byte[] data = sendSecretName(Const.INS_RETRIEVE);
        if (data == null) {
            return false;
        }
        int len = sc.verifyAndDecrypt(data);
        if (inBytes){
            System.out.printf("Secret: %s%n", Arrays.toString(Arrays.copyOf(data, len)));
        } else {
            System.out.printf("Secret: %s%n", new String(data, 0, len, StandardCharsets.UTF_8));
        }
        return true;
    }

    public boolean removeSecret() {
        byte[] data = sendSecretName(Const.INS_REMOVE);
        if (data == null) {
            return false;
        }
        int len = sc.verifyAndDecrypt(data);
        if (data[0] == Const.SUCCESS && len == 1)  {
            System.out.println("Secret successfully removed!");
            return true;
        }
        return false;
    }

    public boolean storeSecret(boolean fill){
        if (!checkPrerequisites(true, true, false, true)) {
            return false;
        }
        byte[] request = new byte[Const.MAX_NAME_LENGTH + Const.MAX_SECRET_LENGTH + 2];
        byte[] secretName;
        byte[] secret;
        if (fill) {
            secretName = new byte[Const.MAX_NAME_LENGTH];
            sc.crypto.genBytes(secretName, 0, Const.MAX_NAME_LENGTH);
            secret = new byte[Const.MAX_SECRET_LENGTH];
            sc.crypto.genBytes(secret, 0, Const.MAX_SECRET_LENGTH);
        } else {
            secretName = getInput("Secret name:", Const.MAX_NAME_LENGTH);
            secret = getInput("Secret:", Const.MAX_SECRET_LENGTH);
        }
        request[0] = (byte) secretName.length;
        System.arraycopy(secretName, 0, request, 1, secretName.length);
        request[secretName.length + 1] = (byte) secret.length;
        System.arraycopy(secret, 0, request, secretName.length + 2, secret.length);
        ResponseAPDU response = sc.secureRespond(request, secretName.length + secret.length + 2,
                Const.INS_STORE, (byte) 0, (byte) 0);
        short sw = (short) response.getSW();
        if (sw == Const.SW_STORAGE_FULL) {
            System.out.println("Secret storage is full");
            return true;
        }
        if (sw == Const.SW_VALUE_ALREADY_PRESENT) {
            System.out.println("Record with same name already present on the card!");
            return true;
        }
        byte[] data = response.getData();
        int len = sc.verifyAndDecrypt(data);
        if (data[0] == Const.SUCCESS && len == 1 && sw == ISO7816.SW_NO_ERROR)  {
            System.out.println("Secret successfully saved!");
            return true;
        }
        return false;
    }

    public boolean listNames() {
        if (!checkPrerequisites(true, false, false, true)) {
            return false;
        }
        byte nextPage = 0;
        ResponseAPDU response = sc.secureRespond(new byte[0], 0, Const.INS_LIST, nextPage, (byte) 0);
        while (true) {
            short sw = (short) response.getSW();
            if (sw != ISO7816.SW_NO_ERROR) {
                System.out.println("Data cannot be listed!");
                return false;
            }
            byte[] data = response.getData();
            int len = sc.verifyAndDecrypt(data);
            if (len == 1) {
                System.out.println("Page empty!");
                return true;
            }
            byte numberOfPages = (byte) (data[0] + 1);
            System.out.printf("Showing secrets on page %d from %d:%n", nextPage + 1, numberOfPages);
            int offset = 1;
            while (offset < len) {
                System.out.printf("%s%n", new String(data, offset + 1, data[offset], StandardCharsets.UTF_8));
                offset += data[offset] + 1;
            }
            if (numberOfPages == 1) {
                break;
            }
            while (true) {
                System.out.print("Choose next page (0 for exit):");
                byte[] page = UserInterface.readLine(3);
                if (page == null || !UserInterface.allDigits(page, page.length)) {
                    System.out.println("Invalid input, only numbers between 0 and 999 are allowed");
                    continue;
                }
                nextPage = (byte) Integer.parseInt(new String(page));
                if (nextPage == 0) {
                    return true;
                }
                if (nextPage > numberOfPages) {
                    System.out.println("Page with this number does not exist!");
                    continue;
                }
                break;
            }
            nextPage -= 1;
            response = sc.secureRespond(new byte[0], 0, Const.INS_LIST, nextPage, (byte) 0);
        }
        return true;
    }

    public boolean showStatus() {
        if (!checkPrerequisites(true, false, false, false)) {
            return false;
        }
        byte[] request = new byte[0];
        ResponseAPDU response = sc.secureRespond(request, request.length, Const.INS_STATUS,
                (byte)0x00, (byte)0x00);
        byte[] data = response.getData();
        int len = data.length;
        if (sc.isOpened()) {
            len = sc.verifyAndDecrypt(data);
        }
        if(len != Const.STATUS_LEN) {
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
        System.out.printf("Number of stored secrets: %d/%d%n", data[6], data[7]);
        return true;
    }

    public boolean unpair(){
        if (!checkPrerequisites(true, true, false, true)) {
            return false;
        }
        byte[] out = new byte[Const.PIN_LENGTH];
        confirmation("UNPAIR", out, 0);
        ResponseAPDU response = sc.secureRespond(out, out.length, Const.INS_UNPAIR,
                (byte)0x00, (byte)0x00);
        if (response.getSW1() == 0x63) {
            sc.pinVerified(false);
            System.err.printf("Provided incorrect PIN, need to sign again with %x attempts!%n",
                    response.getSW2() - 0xc0);
            return false;
        }
        if (response.getSW1() != 0x90) {
            System.err.println("Unpairing cannot be performed!");
            return false;
        }
        sc.reset();
        return true;
    }

    public boolean changePin(byte P1) {
        if (!checkPrerequisites(true, true, false, true)) {
            return false;
        }
        byte[] out;
        ResponseAPDU response;
        switch (P1) {
            case Const.CHANGE_PIN:
                out = new byte[2*Const.PIN_LENGTH];
                confirmation("CHANGE_PIN", out, 0);
                System.out.println("Enter new PIN");
                byte[] pin = UserInterface.getPin(false);
                System.arraycopy(pin, 0, out, Const.PIN_LENGTH, Const.PIN_LENGTH);
                response = sc.secureRespond(out, out.length, Const.INS_CHANGE_PIN,
                        Const.CHANGE_PIN, (byte)0x00);
                if (validPin(response)){
                    System.out.println("PIN successfully changed!");
                }
                break;
            case Const.CHANGE_PUK:
                out = new byte[Const.PIN_LENGTH + Const.PUK_LENGTH];
                confirmation("CHANGE_PUK", out, 0);
                System.out.println("Enter new PUK");
                byte[] puk = UserInterface.getPuk(false);
                System.arraycopy(puk, 0, out, Const.PIN_LENGTH, Const.PUK_LENGTH);
                response = sc.secureRespond(out, out.length, Const.INS_CHANGE_PIN,
                        Const.CHANGE_PUK, (byte)0x00);
                if (validPin(response)) {
                    System.out.println("PUK successfully changed!");
                }
                break;
            case Const.CHANGE_PAIRING_SECRET:
                byte[] ps = new byte[Const.SC_SECRET_LENGTH + Const.PIN_LENGTH];
                confirmation("CHANGE_PAIRING_SECRET", ps, 0);
                sc.crypto.genBytes(ps, Const.PIN_LENGTH, Const.SC_SECRET_LENGTH);
                response = sc.secureRespond(ps, ps.length, Const.INS_CHANGE_PIN,
                        Const.CHANGE_PAIRING_SECRET, (byte)0x00);
                if (validPin(response)) {
                    sc.changePS(ps, Const.PIN_LENGTH, Const.SC_SECRET_LENGTH);
                }
                break;
            default:
                System.err.println("Invalid operation");
                return false;
        }
        return true;
    }

    public boolean unblockPin() {
        if (!checkPrerequisites(true, false, true, false)) {
            return false;
        }
        if (sc.isPermanentlyBlocked()) {
            System.out.println("Card blocked!");
            return false;
        }
        byte[] request;
        ResponseAPDU response;
        int attemptsRemaining;
        byte[] data;
        do{
            byte[] puk = UserInterface.getPuk(false);
            System.out.println("Enter new PIN:");
            byte[] pin = UserInterface.getPin(false);
            request = Arrays.copyOf(puk,  puk.length + pin.length);
            System.arraycopy(pin, 0, request, puk.length, pin.length);
            response = sc.secureRespond(request, request.length, Const.INS_UNBLOCK_PIN,
                    (byte)0x00, (byte)0x00);
            if ((short) response.getSW() != ISO7816.SW_NO_ERROR) {
                attemptsRemaining = response.getSW2() - 0xc0;
                if (attemptsRemaining <= 0) {
                    System.out.println("Card blocked permanently!");
                    sc.cardBlocked(true);
                    return false;
                }
                System.out.printf("Invalid PUK, remains %x attempts%n", attemptsRemaining);
            }
        } while ((short) response.getSW() != ISO7816.SW_NO_ERROR);
        data = response.getData();
        int len = sc.verifyAndDecrypt(data);
        if (data[0] == Const.SUCCESS && len == 1) {
            System.out.println("PIN changed");
            sc.pinBlocked(false);
            sc.pinVerified(true);
            return true;
        }
        System.out.println("Failed to verify PUK");
        return false;
    }

    public boolean verifyPin() {
        if (!checkPrerequisites(true, false, false, true)) {
            return false;
        }
        ResponseAPDU response;
        byte[] pin = UserInterface.getPin(false);
        response = sc.secureRespond(pin, pin.length, Const.INS_VERIFY_PIN,
                (byte)0x00, (byte)0x00);
        if (validPin(response)) {
            sc.pinVerified(true);
            System.out.println("PIN verified!");
        }
       return true;
    }

    public void selectApp() throws Exception {
        sc.reset();
        byte[] select_response = Run.simulator.selectAppletWithResult(Run.appletAID);
        switch (select_response[0]){
            case Const.RET_NOT_INIT:
                System.out.println("Card not initialized, starting first time setup...\n");
                sc.initialize(select_response);
                return;
            case Const.RET_INITIALIZED:
                System.out.println("Card already initialized, starting...\n");
                return;
            default:
                throw new RuntimeException();
        }
    }
}
