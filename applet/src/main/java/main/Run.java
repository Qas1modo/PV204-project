package main;

import applet.SecretStorageApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;

import javax.smartcardio.*;
import javax.smartcardio.CardException;

public class  Run {
    private static CardTerminal cardTerminal = null;
    private static CardChannel channel = null;
    public static final CardSimulator simulator = new CardSimulator();
    public static final AID appletAID = AIDUtil.create("F000000001");
    public static boolean inSimulator = true;

    public static final byte[] APPLET_ID = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02};
    public static void main(String[] args){
        SecretStorageAPDU application = new SecretStorageAPDU();
        if (inSimulator) {
            simulator.installApplet(appletAID, SecretStorageApplet.class);
        } else if(!openCardChannel()) {
            return;
        }
        UserInterface ui = new UserInterface(application);
        ui.start();
    }

    private static boolean openCardChannel() {
        try {
            TerminalFactory tf = TerminalFactory.getInstance("PC/SC", null);
            for (CardTerminal t : tf.terminals().list()) {
                if (t.isCardPresent()) {
                    cardTerminal = t;
                    break;
                }
            }
            if (cardTerminal == null){
                System.out.println("No card connected!");
                return false;
            }
        Card card = cardTerminal.connect("*");
        channel = card.getBasicChannel();
        } catch (Exception e) {
            System.out.println("Failed to open card channel.");
            return false;
        }
        return true;
    }

    public static byte[] select(){
        if (inSimulator) {
            return Run.simulator.selectAppletWithResult(Run.appletAID);
        }
        else {
            CommandAPDU cmd = new CommandAPDU(0x00, 0xa4, 0x04, 0x00, APPLET_ID);
            ResponseAPDU response = transmit(cmd);
            return response.getData();
        }
    }

    public static ResponseAPDU transmit(CommandAPDU commandAPDU) {
        if (inSimulator) {
            return Run.simulator.transmitCommand(commandAPDU);
        }
        try {
            return channel.transmit(commandAPDU);
        } catch (CardException e) {
            throw new RuntimeException("Failed to communicate with card");
        }
    }
}