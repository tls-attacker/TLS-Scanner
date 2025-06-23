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

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private InvalidCurveTestInfo() {
        this.vector = null;
    }

    /**
     * Constructs a new InvalidCurveTestInfo with the specified vector.
     *
     * @param vector the invalid curve vector to test
     */
    public InvalidCurveTestInfo(InvalidCurveVector vector) {
        this.vector = vector;
    }

    /**
     * Returns a technical name for this test info.
     *
     * @return the string representation of the invalid curve vector
     */
    @Override
    public String getTechnicalName() {
        return getVector().toString();
    }

    /**
     * Returns the names of the fields in this test info.
     *
     * @return a list containing a single element "Vector"
     */
    @Override
    public List<String> getFieldNames() {
        return Collections.singletonList("Vector");
    }

    /**
     * Returns the values of the fields in this test info.
     *
     * @return a list containing the string representation of the vector
     */
    @Override
    public List<String> getFieldValues() {
        return Collections.singletonList(getVector().toString());
    }

    /**
     * Returns a human-readable name for this test info.
     *
     * @return the string representation of the invalid curve vector
     */
    @Override
    public String getPrintableName() {
        return getVector().toString();
    }

    /**
     * Checks if this test info is equal to another object.
     *
     * @param o the object to compare with
     * @return true if the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (o instanceof InvalidCurveTestInfo) {
            InvalidCurveTestInfo other = (InvalidCurveTestInfo) o;
            return other.getVector().equals(vector);
        }
        return false;
    }

    /**
     * Returns a hash code value for this test info.
     *
     * @return the hash code value
     */
    @Override
    public int hashCode() {
        int hashCode = 7;
        hashCode *= getVector().hashCode();
        return hashCode;
    }

    /**
     * Returns the invalid curve vector for this test.
     *
     * @return the invalid curve vector
     */
    public InvalidCurveVector getVector() {
        return vector;
    }
}
