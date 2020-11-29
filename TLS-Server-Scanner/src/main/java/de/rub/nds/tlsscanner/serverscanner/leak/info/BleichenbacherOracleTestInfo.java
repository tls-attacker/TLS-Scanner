/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.serverscanner.leak.info;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class BleichenbacherOracleTestInfo extends TestInfo {

    private final ProtocolVersion version;

    private final CipherSuite cipherSuite;

    private final BleichenbacherWorkflowType bleichenbacherWorkflowType;

    private final BleichenbacherCommandConfig.Type bleichenbacherType;

    public BleichenbacherOracleTestInfo(ProtocolVersion version, CipherSuite cipherSuite,
            BleichenbacherWorkflowType bleichenbacherWorkflowType, BleichenbacherCommandConfig.Type bleichenbacherType) {
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

    public BleichenbacherCommandConfig.Type getBleichenbacherType() {
        return bleichenbacherType;
    }

}
