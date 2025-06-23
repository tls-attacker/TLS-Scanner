/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import java.util.List;

/**
 * Abstract base class for test information objects that provide metadata about statistical tests.
 * Implementations must provide technical and human-readable names, as well as field information.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public abstract class TestInfo {

    /**
     * Returns the technical name of the test, typically used for internal identification.
     *
     * @return The technical name of the test
     */
    public abstract String getTechnicalName();

    /**
     * Returns a list of field names associated with this test.
     *
     * @return List of field names
     */
    public abstract List<String> getFieldNames();

    /**
     * Returns a list of field values corresponding to the field names.
     *
     * @return List of field values
     */
    public abstract List<String> getFieldValues();

    /**
     * Returns a human-readable name for the test suitable for display purposes.
     *
     * @return The printable name of the test
     */
    public abstract String getPrintableName();

    @Override
    public abstract boolean equals(Object o);

    @Override
    public abstract int hashCode();
}
