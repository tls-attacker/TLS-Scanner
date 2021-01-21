/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.serverscanner.leak.info;

import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.InvalidCurveVector;

public class InvalidCurveTestInfo extends TestInfo {

    private final InvalidCurveVector vector;

    public InvalidCurveTestInfo(InvalidCurveVector vector) {
        this.vector = vector;
    }

    @Override
    public String getTechnicalName() {
        return getVector().toString();
    }

    @Override
    public String getPrintableName() {
        return getVector().toString();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof InvalidCurveTestInfo) {
            InvalidCurveTestInfo other = (InvalidCurveTestInfo) o;
            return other.getVector().equals(vector);
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hashCode = 7;
        hashCode *= getVector().hashCode();
        return hashCode;
    }

    public InvalidCurveVector getVector() {
        return vector;
    }

}
