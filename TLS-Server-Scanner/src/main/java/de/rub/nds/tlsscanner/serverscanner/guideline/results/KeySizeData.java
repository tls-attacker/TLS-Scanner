/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.protocol.constants.AsymmetricAlgorithmType;

public class KeySizeData {
    private AsymmetricAlgorithmType algorithm;
    private int minimumLength;
    private int actualLength;

    public KeySizeData(AsymmetricAlgorithmType algorithm, int minimumLength, int actualLength) {
        this.algorithm = algorithm;
        this.minimumLength = minimumLength;
        this.actualLength = actualLength;
    }

    public AsymmetricAlgorithmType getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(AsymmetricAlgorithmType algorithm) {
        this.algorithm = algorithm;
    }

    public int getMinimumLength() {
        return minimumLength;
    }

    public void setMinimumLength(int minimumLength) {
        this.minimumLength = minimumLength;
    }

    public int getActualLength() {
        return actualLength;
    }

    public void setActualLength(int actualLength) {
        this.actualLength = actualLength;
    }
}
