/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.rub.nds.tlsscanner.serverscanner.leak.info;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.directraccoon.DirectRaccoonWorkflowType;

/**
 *
 * @author robert
 */
public class DirectRaccoonOracleTestInfo extends TestInfo {

    private final CipherSuite cipherSuite;

    private final ProtocolVersion version;

    private final DirectRaccoonWorkflowType directWorkflowType;

    public DirectRaccoonOracleTestInfo(CipherSuite suite, ProtocolVersion version,
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
    public String getPrintableName() {
        return "" + version.name() + "\t" + cipherSuite.name();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof DirectRaccoonOracleTestInfo) {
            DirectRaccoonOracleTestInfo other = (DirectRaccoonOracleTestInfo) o;
            if (other.getDirectWorkflowType().equals(this.getDirectWorkflowType())) {
                if (other.getVersion().equals(this.getVersion())) {
                    if (other.getCipherSuite().equals(this.getCipherSuite())) {
                        return true;
                    }
                }
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
