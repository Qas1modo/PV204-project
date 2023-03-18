package APDU;

import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;

import com.licel.jcardsim.smartcardio.CardSimulator;
import javax.smartcardio.*;

public class Simulator {
    private static final String APPLET_AID = "73696d706c656170706c6574";
    private final CardSimulator simulator;

    public static void main(String[] args) {
        try {
            Simulator main = new Simulator();
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public Simulator() {
        simulator = new CardSimulator();
        AID applet = AIDUtil.create(APPLET_AID);
        //simulator.installApplet(applet, SecretStorage.class);
        simulator.selectApplet(applet);
    }

    public ResponseAPDU SendData(byte[] command) {
        CommandAPDU commandAPDU = new CommandAPDU(command);
        return simulator.transmitCommand(commandAPDU);
    }
}
