package de.rub.nds.tlsscanner.report.result.hpkp;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

public class HpkpPin {

    private String pinType;
    private byte[] pin;

    public HpkpPin(String pinType, byte[] ping) {
        this.pinType = pinType;
        this.pin = ping;
    }

    public String getPinType() {
        return pinType;
    }

    public void setPinType(String pinType) {
        this.pinType = pinType;
    }

    public byte[] getPing() {
        return pin;
    }

    public void setPing(byte[] ping) {
        this.pin = ping;
    }

    @Override
    public String toString() {
        return "" + pinType.trim() + " - " + ArrayConverter.bytesToHexString(pin, false, false).replace(" ", "");
    }
}
