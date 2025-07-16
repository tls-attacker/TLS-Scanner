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
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherScanType;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherWorkflowType;
import java.util.Arrays;
import java.util.List;

public class BleichenbacherOracleTestInfo extends TestInfo {

    private final ProtocolVersion version;

    private final CipherSuite cipherSuite;

    private final BleichenbacherWorkflowType bleichenbacherWorkflowType;

    private final BleichenbacherScanType bleichenbacherType;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private BleichenbacherOracleTestInfo() {
        this.version = null;
        this.cipherSuite = null;
        this.bleichenbacherWorkflowType = null;
        this.bleichenbacherType = null;
    }

    /**
     * Constructs a new BleichenbacherOracleTestInfo with the specified parameters.
     *
     * @param version the protocol version to test
     * @param cipherSuite the cipher suite to test
     * @param bleichenbacherWorkflowType the type of Bleichenbacher workflow to use
     * @param bleichenbacherType the type of Bleichenbacher scan to perform
     */
    public BleichenbacherOracleTestInfo(
            ProtocolVersion version,
            CipherSuite cipherSuite,
            BleichenbacherWorkflowType bleichenbacherWorkflowType,
            BleichenbacherScanType bleichenbacherType) {
        this.version = version;
        this.cipherSuite = cipherSuite;
        this.bleichenbacherWorkflowType = bleichenbacherWorkflowType;
        this.bleichenbacherType = bleichenbacherType;
    }

    /**
     * Returns a technical name for this test info combining all test parameters.
     *
     * @return a colon-separated string of scan type, workflow type, version, and cipher suite
     */
    @Override
    public String getTechnicalName() {
        return bleichenbacherType.name()
                + ":"
                + bleichenbacherWorkflowType.name()
                + ":"
                + version.name()
                + ":"
                + cipherSuite.name();
    }

    /**
     * Returns the names of the fields in this test info.
     *
     * @return a list containing the field names
     */
    @Override
    public List<String> getFieldNames() {
        return Arrays.asList("Scan Type, Workflow Type", "Version", "CipherSuite");
    }

    /**
     * Returns the values of the fields in this test info.
     *
     * @return a list containing the field values as strings
     */
    @Override
    public List<String> getFieldValues() {
        return Arrays.asList(
                bleichenbacherType.name(),
                bleichenbacherWorkflowType.name(),
                version.name(),
                cipherSuite.name());
    }

    /**
     * Returns a human-readable name for this test info.
     *
     * @return a tab-separated string of scan type, workflow type, version, and cipher suite
     */
    @Override
    public String getPrintableName() {
        return bleichenbacherType.name()
                + "\t"
                + bleichenbacherWorkflowType.name()
                + "\t"
                + version.name()
                + "\t"
                + cipherSuite.name();
    }

    /**
     * Checks if this test info is equal to another object.
     *
     * @param o the object to compare with
     * @return true if the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (o instanceof BleichenbacherOracleTestInfo) {
            BleichenbacherOracleTestInfo other = (BleichenbacherOracleTestInfo) o;
            if (other.getBleichenbacherType().equals(this.getBleichenbacherType())
                    && other.getBleichenbacherWorkflowType()
                            .equals(this.getBleichenbacherWorkflowType())
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
        hashCode *= getBleichenbacherType().hashCode();
        hashCode *= getBleichenbacherWorkflowType().hashCode();
        hashCode *= getVersion().hashCode();
        hashCode *= getCipherSuite().hashCode();
        return hashCode;
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
     * Returns the cipher suite for this test.
     *
     * @return the cipher suite
     */
    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    /**
     * Returns the Bleichenbacher workflow type for this test.
     *
     * @return the Bleichenbacher workflow type
     */
    public BleichenbacherWorkflowType getBleichenbacherWorkflowType() {
        return bleichenbacherWorkflowType;
    }

    /**
     * Returns the Bleichenbacher scan type for this test.
     *
     * @return the Bleichenbacher scan type
     */
    public BleichenbacherScanType getBleichenbacherType() {
        return bleichenbacherType;
    }
}
