/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.hpkp;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

public class HpkpPin {

    private String pinType;
    private byte[] pin;

    private HpkpPin() {
    }

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
