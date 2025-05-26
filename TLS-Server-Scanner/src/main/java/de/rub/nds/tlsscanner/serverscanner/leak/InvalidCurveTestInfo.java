/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.leak;

import de.rub.nds.tlsscanner.core.vector.statistics.TestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.vector.InvalidCurveVector;
import java.util.Collections;
import java.util.List;

public class InvalidCurveTestInfo extends TestInfo {

    private final InvalidCurveVector vector;

    @SuppressWarnings("unused")
    // Default constructor for deserialization
    private InvalidCurveTestInfo() {
        this.vector = null;
    }

    public InvalidCurveTestInfo(InvalidCurveVector vector) {
        this.vector = vector;
    }

    @Override
    public String getTechnicalName() {
        return getVector().toString();
    }

    @Override
    public List<String> getFieldNames() {
        return Collections.singletonList("Vector");
    }

    @Override
    public List<String> getFieldValues() {
        return Collections.singletonList(getVector().toString());
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
