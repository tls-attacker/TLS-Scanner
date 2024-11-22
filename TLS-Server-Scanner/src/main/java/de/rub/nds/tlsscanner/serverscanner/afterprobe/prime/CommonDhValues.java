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

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
    private CommonDhValues() {}

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

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public BigInteger getGenerator() {
        return generator;
    }

    public void setGenerator(BigInteger generator) {
        this.generator = generator;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public boolean isPrime() {
        return prime;
    }

    public void setPrime(boolean prime) {
        this.prime = prime;
    }

    public boolean isSafePrime() {
        return safePrime;
    }

    public void setSafePrime(boolean safePrime) {
        this.safePrime = safePrime;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
