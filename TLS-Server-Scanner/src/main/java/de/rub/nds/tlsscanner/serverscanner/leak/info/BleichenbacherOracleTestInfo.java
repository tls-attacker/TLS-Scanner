/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.leak.info;

import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.BleichenbacherScanType;

public class BleichenbacherOracleTestInfo extends TestInfo {

    private final ProtocolVersion version;

    private final CipherSuite cipherSuite;

    private final BleichenbacherWorkflowType bleichenbacherWorkflowType;

    private final BleichenbacherScanType bleichenbacherType;

    public BleichenbacherOracleTestInfo(ProtocolVersion version, CipherSuite cipherSuite,
        BleichenbacherWorkflowType bleichenbacherWorkflowType, BleichenbacherScanType bleichenbacherType) {
        this.version = version;
        this.cipherSuite = cipherSuite;
        this.bleichenbacherWorkflowType = bleichenbacherWorkflowType;
        this.bleichenbacherType = bleichenbacherType;
    }

    @Override
    public String getTechnicalName() {
        return bleichenbacherType.name() + ":" + bleichenbacherWorkflowType.name() + ":" + version.name() + ":"
            + cipherSuite.name();
    }

    @Override
    public String getPrintableName() {
        return bleichenbacherType.name() + "\t" + bleichenbacherWorkflowType.name() + "\t" + version.name() + "\t"
            + cipherSuite.name();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof BleichenbacherOracleTestInfo) {
            BleichenbacherOracleTestInfo other = (BleichenbacherOracleTestInfo) o;
            if (other.getBleichenbacherType().equals(this.getBleichenbacherType())) {
                if (other.getBleichenbacherWorkflowType().equals(this.getBleichenbacherWorkflowType())) {
                    if (other.getVersion().equals(this.getVersion())) {
                        if (other.getCipherSuite().equals(this.getCipherSuite())) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hashCode = 7;
        hashCode *= getBleichenbacherType().hashCode();
        hashCode *= getBleichenbacherWorkflowType().hashCode();
        hashCode *= getVersion().hashCode();
        hashCode *= getCipherSuite().hashCode();
        return hashCode;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public BleichenbacherWorkflowType getBleichenbacherWorkflowType() {
        return bleichenbacherWorkflowType;
    }

    public BleichenbacherScanType getBleichenbacherType() {
        return bleichenbacherType;
    }

}
