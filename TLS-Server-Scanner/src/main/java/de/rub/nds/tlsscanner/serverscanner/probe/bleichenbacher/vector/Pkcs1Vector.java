/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.core.vector.Vector;
import java.util.Arrays;
import java.util.Objects;

public class Pkcs1Vector implements Vector {

    private String name;

    private byte[] plainValue;

    private byte[] encryptedValue;

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
    private Pkcs1Vector() {}

    public Pkcs1Vector(String name, byte[] value) {
        this.name = name;
        this.plainValue = value;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getPlainValue() {
        return plainValue;
    }

    public void setPlainValue(byte[] plainValue) {
        this.plainValue = plainValue;
    }

    public byte[] getEncryptedValue() {
        return encryptedValue;
    }

    public void setEncryptedValue(byte[] encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + Objects.hashCode(this.name);
        hash = 67 * hash + Arrays.hashCode(this.plainValue);
        hash = 67 * hash + Arrays.hashCode(this.encryptedValue);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Pkcs1Vector other = (Pkcs1Vector) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Arrays.equals(this.plainValue, other.plainValue)) {
            return false;
        }
        return Arrays.equals(this.encryptedValue, other.encryptedValue);
    }

    @Override
    public String toString() {
        return ""
                + name
                + "{"
                + "plainValue="
                + ArrayConverter.bytesToHexString(plainValue)
                + ", encryptedValue="
                + ArrayConverter.bytesToHexString(encryptedValue)
                + '}';
    }
}
