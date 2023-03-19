package main;

import applet.SecretStorageApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;

public class Run {
    public static final CardSimulator simulator = new CardSimulator();
    public static final AID appletAID = AIDUtil.create("F000000001");;
    public static void main(String[] args){
        SecretStorageAPDU application = new SecretStorageAPDU();
        simulator.installApplet(appletAID, SecretStorageApplet.class);
        application.ui.start();
    }
}