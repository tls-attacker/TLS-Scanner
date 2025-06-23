/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.leak;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.vector.statistics.TestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.directraccoon.DirectRaccoonWorkflowType;
import java.util.Arrays;
import java.util.List;

public class DirectRaccoonOracleTestInfo extends TestInfo {

    private final CipherSuite cipherSuite;

    private final ProtocolVersion version;

    private final DirectRaccoonWorkflowType directWorkflowType;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private DirectRaccoonOracleTestInfo() {
        this.cipherSuite = null;
        this.version = null;
        this.directWorkflowType = null;
    }

    /**
     * Constructs a new DirectRaccoonOracleTestInfo with the specified parameters.
     *
     * @param suite the cipher suite to test
     * @param version the protocol version to test
     * @param directWorkflowType the type of Direct Raccoon workflow to use
     */
    public DirectRaccoonOracleTestInfo(
            CipherSuite suite,
            ProtocolVersion version,
            DirectRaccoonWorkflowType directWorkflowType) {
        this.cipherSuite = suite;
        this.version = version;
        this.directWorkflowType = directWorkflowType;
    }

    /**
     * Returns a technical name for this test info combining all test parameters.
     *
     * @return a colon-separated string of workflow type, version, and cipher suite
     */
    @Override
    public String getTechnicalName() {
        return directWorkflowType.name() + ":" + version.name() + ":" + cipherSuite.name();
    }

    /**
     * Returns the names of the fields in this test info.
     *
     * @return a list containing the field names
     */
    @Override
    public List<String> getFieldNames() {
        return Arrays.asList("Workflow Type", "Version", "CipherSuite");
    }

    /**
     * Returns the values of the fields in this test info.
     *
     * @return a list containing the field values as strings
     */
    @Override
    public List<String> getFieldValues() {
        return Arrays.asList(directWorkflowType.name(), version.name(), cipherSuite.name());
    }

    /**
     * Returns a human-readable name for this test info.
     *
     * @return a tab-separated string of version and cipher suite
     */
    @Override
    public String getPrintableName() {
        return "" + version.name() + "\t" + cipherSuite.name();
    }

    /**
     * Checks if this test info is equal to another object.
     *
     * @param o the object to compare with
     * @return true if the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (o instanceof DirectRaccoonOracleTestInfo) {
            DirectRaccoonOracleTestInfo other = (DirectRaccoonOracleTestInfo) o;
            if (other.getDirectWorkflowType().equals(this.getDirectWorkflowType())
                    && other.getVersion().equals(this.getVersion())
                    && other.getCipherSuite().equals(this.getCipherSuite())) {
                return true;
            }
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
        hashCode *= getDirectWorkflowType().hashCode();
        hashCode *= getVersion().hashCode();
        hashCode *= getCipherSuite().hashCode();
        return hashCode;
    }

    /**
     * Returns the cipher suite for this test.
     *
     * @return the cipher suite
     */
    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    /**
     * Returns the protocol version for this test.
     *
     * @return the protocol version
     */
    public ProtocolVersion getVersion() {
        return version;
    }

    /**
     * Returns the Direct Raccoon workflow type for this test.
     *
     * @return the Direct Raccoon workflow type
     */
    public DirectRaccoonWorkflowType getDirectWorkflowType() {
        return directWorkflowType;
    }
}
