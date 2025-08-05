/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp;

import de.rub.nds.modifiablevariable.util.DataConverter;

public class HpkpPin {

    private String pinType;
    private byte[] pin;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private HpkpPin() {}

    /**
     * Constructs a new HpkpPin with the specified pin type and pin value.
     *
     * @param pinType the type of the pin (e.g., "sha256")
     * @param ping the pin value as a byte array
     */
    public HpkpPin(String pinType, byte[] ping) {
        this.pinType = pinType;
        this.pin = ping;
    }

    /**
     * Returns the type of the pin.
     *
     * @return the pin type (e.g., "sha256")
     */
    public String getPinType() {
        return pinType;
    }

    /**
     * Sets the type of the pin.
     *
     * @param pinType the pin type to set (e.g., "sha256")
     */
    public void setPinType(String pinType) {
        this.pinType = pinType;
    }

    /**
     * Returns the pin value as a byte array.
     *
     * @return the pin value
     */
    public byte[] getPing() {
        return pin;
    }

    /**
     * Sets the pin value.
     *
     * @param ping the pin value to set as a byte array
     */
    public void setPing(byte[] ping) {
        this.pin = ping;
    }

    /**
     * Returns a string representation of this HpkpPin.
     *
     * @return a string containing the pin type and pin value in hexadecimal format
     */
    @Override
    public String toString() {
        return ""
                + pinType.trim()
                + " - "
                + DataConverter.bytesToHexString(pin, false, false).replace(" ", "");
    }
}
