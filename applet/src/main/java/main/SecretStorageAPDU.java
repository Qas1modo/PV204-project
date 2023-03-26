package main;

import javax.smartcardio.ResponseAPDU;
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

    private void confirmation(String operation, byte[] buffer, int off) {
        System.out.printf("Confirm operation %s by providing correct PIN%n", operation);
        byte[] pin = UserInterface.getPin(false);
        System.arraycopy(pin, 0, buffer, off, Const.PIN_LENGTH);
    }

    private boolean validPin(ResponseAPDU response) {
        if (response.getSW1() == 0x90) {
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


    public boolean showStatus() {
        if (!checkPrerequisites(true, false, false, false)) {
            return false;
        }
        byte[] request = new byte[0];
        ResponseAPDU response = sc.secureRespond(request, (short) request.length, Const.INS_STATUS,
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
        return true;
    }

    public boolean unpair(){
        if (!checkPrerequisites(true, true, false, true)) {
            return false;
        }
        byte[] out = new byte[Const.PIN_LENGTH];
        confirmation("UNPAIR", out, 0);
        ResponseAPDU response = sc.secureRespond(out, (short) out.length, Const.INS_UNPAIR,
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
        ResponseAPDU response;
        switch (P1) {
            case Const.CHANGE_PIN:
                byte[] out = new byte[2*Const.PIN_LENGTH];
                confirmation("CHANGE_PIN", out, 0);
                System.out.println("Enter new PIN");
                byte[] pin = UserInterface.getPin(false);
                System.arraycopy(pin, 0, out, Const.PIN_LENGTH, Const.PIN_LENGTH);
                response = sc.secureRespond(out, (short) out.length, Const.INS_CHANGE_PIN,
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
                response = sc.secureRespond(out, (short) out.length, Const.INS_CHANGE_PIN,
                        Const.CHANGE_PUK, (byte)0x00);
                if (validPin(response)) {
                    System.out.println("PUK successfully changed!");
                }
                break;
            case Const.CHANGE_PAIRING_SECRET:
                byte[] ps = new byte[Const.SC_SECRET_LENGTH + Const.PIN_LENGTH];
                confirmation("CHANGE_PAIRING_SECRET", ps, 0);
                sc.crypto.genBytes(ps, Const.PIN_LENGTH, Const.SC_SECRET_LENGTH);
                response = sc.secureRespond(ps, (short) ps.length, Const.INS_CHANGE_PIN,
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
            response = sc.secureRespond(request, (short) request.length, Const.INS_UNBLOCK_PIN,
                    (byte)0x00, (byte)0x00);
            if (response.getSW1() != 0x90) {
                attemptsRemaining = response.getSW2() - 0xc0;
                if (attemptsRemaining <= 0) {
                    System.out.println("Card blocked permanently!");
                    sc.cardBlocked(true);
                    return false;
                }
                System.out.printf("Invalid PUK, remains %x attempts%n", attemptsRemaining);
            }
        } while (response.getSW1() != 0x90);
        data = response.getData();
        int len = sc.verifyAndDecrypt(data);
        if (data[0] == 0x01 && len == 1) {
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
        response = sc.secureRespond(pin, (short) pin.length, Const.INS_VERIFY_PIN,
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
