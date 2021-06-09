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

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

/**
 *
 * @author robert
 */
public class PaddingOracleTestInfo extends TestInfo {

    private final ProtocolVersion version;

    private final CipherSuite cipherSuite;

    private final PaddingVectorGeneratorType vectorGeneratorType;

    private final PaddingRecordGeneratorType recordGeneratorType;

    public PaddingOracleTestInfo(ProtocolVersion version, CipherSuite suite,
        PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType recordGeneratorType) {
        this.version = version;
        this.cipherSuite = suite;
        this.vectorGeneratorType = vectorGeneratorType;
        this.recordGeneratorType = recordGeneratorType;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public PaddingVectorGeneratorType getVectorGeneratorType() {
        return vectorGeneratorType;
    }

    public PaddingRecordGeneratorType getRecordGeneratorType() {
        return recordGeneratorType;
    }

    @Override
    public String getTechnicalName() {
        return vectorGeneratorType.name() + ":" + recordGeneratorType.name() + ":" + version.name() + ":"
            + cipherSuite.name();
    }

    @Override
    public String getPrintableName() {
        return vectorGeneratorType.name() + "\t" + recordGeneratorType.name() + "\t" + version.name() + "\t"
            + cipherSuite.name();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof PaddingOracleTestInfo) {
            PaddingOracleTestInfo other = (PaddingOracleTestInfo) o;
            if (other.getVectorGeneratorType().equals(this.getVectorGeneratorType())) {
                if (other.getRecordGeneratorType().equals(this.getRecordGeneratorType())) {
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
        hashCode *= getVectorGeneratorType().hashCode();
        hashCode *= getRecordGeneratorType().hashCode();
        hashCode *= getVersion().hashCode();
        hashCode *= getCipherSuite().hashCode();
        return hashCode;
    }
}
