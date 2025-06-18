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

    public DirectRaccoonOracleTestInfo(
            CipherSuite suite,
            ProtocolVersion version,
            DirectRaccoonWorkflowType directWorkflowType) {
        this.cipherSuite = suite;
        this.version = version;
        this.directWorkflowType = directWorkflowType;
    }

    @Override
    public String getTechnicalName() {
        return directWorkflowType.name() + ":" + version.name() + ":" + cipherSuite.name();
    }

    @Override
    public List<String> getFieldNames() {
        return Arrays.asList("Workflow Type", "Version", "CipherSuite");
    }

    @Override
    public List<String> getFieldValues() {
        return Arrays.asList(directWorkflowType.name(), version.name(), cipherSuite.name());
    }

    @Override
    public String getPrintableName() {
        return "" + version.name() + "\t" + cipherSuite.name();
    }

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

    @Override
    public int hashCode() {
        int hashCode = 7;
        hashCode *= getDirectWorkflowType().hashCode();
        hashCode *= getVersion().hashCode();
        hashCode *= getCipherSuite().hashCode();
        return hashCode;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public DirectRaccoonWorkflowType getDirectWorkflowType() {
        return directWorkflowType;
    }
}
