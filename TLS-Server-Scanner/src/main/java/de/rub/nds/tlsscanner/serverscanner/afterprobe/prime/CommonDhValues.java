/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe.prime;

import java.io.Serializable;
import java.math.BigInteger;

public class CommonDhValues implements Serializable {

    private BigInteger generator;
    private BigInteger modulus;
    private int length;
    private boolean prime;
    private boolean safePrime;
    private String name;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private CommonDhValues() {}

    /**
     * Constructs a CommonDhValues object with the specified Diffie-Hellman parameters.
     *
     * @param generator the generator value for the Diffie-Hellman group
     * @param modulus the modulus (prime) value for the Diffie-Hellman group
     * @param length the bit length of the modulus
     * @param prime whether the modulus is a prime number
     * @param safePrime whether the modulus is a safe prime (p = 2q + 1)
     * @param name the name or identifier for this set of DH parameters
     */
    public CommonDhValues(
            BigInteger generator,
            BigInteger modulus,
            int length,
            boolean prime,
            boolean safePrime,
            String name) {
        this.generator = generator;
        this.modulus = modulus;
        this.length = length;
        this.prime = prime;
        this.safePrime = safePrime;
        this.name = name;
    }

    /**
     * Returns the bit length of the modulus.
     *
     * @return the bit length of the modulus
     */
    public int getLength() {
        return length;
    }

    /**
     * Sets the bit length of the modulus.
     *
     * @param length the bit length to set
     */
    public void setLength(int length) {
        this.length = length;
    }

    /**
     * Returns the generator value for the Diffie-Hellman group.
     *
     * @return the generator value
     */
    public BigInteger getGenerator() {
        return generator;
    }

    /**
     * Sets the generator value for the Diffie-Hellman group.
     *
     * @param generator the generator value to set
     */
    public void setGenerator(BigInteger generator) {
        this.generator = generator;
    }

    /**
     * Returns the modulus (prime) value for the Diffie-Hellman group.
     *
     * @return the modulus value
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /**
     * Sets the modulus (prime) value for the Diffie-Hellman group.
     *
     * @param modulus the modulus value to set
     */
    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    /**
     * Returns whether the modulus is a prime number.
     *
     * @return true if the modulus is prime, false otherwise
     */
    public boolean isPrime() {
        return prime;
    }

    /**
     * Sets whether the modulus is a prime number.
     *
     * @param prime true if the modulus is prime, false otherwise
     */
    public void setPrime(boolean prime) {
        this.prime = prime;
    }

    /**
     * Returns whether the modulus is a safe prime (p = 2q + 1).
     *
     * @return true if the modulus is a safe prime, false otherwise
     */
    public boolean isSafePrime() {
        return safePrime;
    }

    /**
     * Sets whether the modulus is a safe prime (p = 2q + 1).
     *
     * @param safePrime true if the modulus is a safe prime, false otherwise
     */
    public void setSafePrime(boolean safePrime) {
        this.safePrime = safePrime;
    }

    /**
     * Returns the name or identifier for this set of DH parameters.
     *
     * @return the name of the DH parameters
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the name or identifier for this set of DH parameters.
     *
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }
}
