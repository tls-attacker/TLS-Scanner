/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsscanner.core.vector.Vector;
import java.util.Arrays;
import java.util.Objects;

public class Pkcs1Vector implements Vector {

    private String name;

    private byte[] plainValue;

    private byte[] encryptedValue;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private Pkcs1Vector() {}

    /**
     * Creates a new PKCS#1 vector with the specified name and plain value.
     *
     * @param name the name of the vector
     * @param value the plain (unencrypted) value of the vector
     */
    public Pkcs1Vector(String name, byte[] value) {
        this.name = name;
        this.plainValue = value;
    }

    /**
     * Gets the name of this PKCS#1 vector.
     *
     * @return the name of the vector
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * Sets the name of this PKCS#1 vector.
     *
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets the plain (unencrypted) value of this PKCS#1 vector.
     *
     * @return the plain value as a byte array
     */
    public byte[] getPlainValue() {
        return plainValue;
    }

    /**
     * Sets the plain (unencrypted) value of this PKCS#1 vector.
     *
     * @param plainValue the plain value to set
     */
    public void setPlainValue(byte[] plainValue) {
        this.plainValue = plainValue;
    }

    /**
     * Gets the encrypted value of this PKCS#1 vector.
     *
     * @return the encrypted value as a byte array
     */
    public byte[] getEncryptedValue() {
        return encryptedValue;
    }

    /**
     * Sets the encrypted value of this PKCS#1 vector.
     *
     * @param encryptedValue the encrypted value to set
     */
    public void setEncryptedValue(byte[] encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    /**
     * Computes the hash code for this PKCS#1 vector based on its name, plain value, and encrypted
     * value.
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + Objects.hashCode(this.name);
        hash = 67 * hash + Arrays.hashCode(this.plainValue);
        hash = 67 * hash + Arrays.hashCode(this.encryptedValue);
        return hash;
    }

    /**
     * Determines whether this PKCS#1 vector is equal to another object. Two vectors are considered
     * equal if they have the same name, plain value, and encrypted value.
     *
     * @param obj the object to compare with
     * @return true if the objects are equal, false otherwise
     */
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

    /**
     * Returns a string representation of this PKCS#1 vector, including its name and hexadecimal
     * representations of the plain and encrypted values.
     *
     * @return a string representation of the vector
     */
    @Override
    public String toString() {
        return ""
                + name
                + "{"
                + "plainValue="
                + DataConverter.bytesToHexString(plainValue)
                + ", encryptedValue="
                + DataConverter.bytesToHexString(encryptedValue)
                + '}';
    }
}
