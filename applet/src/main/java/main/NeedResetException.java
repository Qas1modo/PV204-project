package main;

public class NeedResetException extends Exception{
    boolean pairingRemoved = false;

    public NeedResetException() {
    }

    public NeedResetException(boolean pairingRemoved) {
        this.pairingRemoved = pairingRemoved;
    }
}
