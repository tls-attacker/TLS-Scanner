/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.leak;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsscanner.core.vector.statistics.TestInfo;
import java.util.Arrays;
import java.util.List;

public class PaddingOracleTestInfo extends TestInfo {

    private final ProtocolVersion version;

    private final CipherSuite cipherSuite;

    private final PaddingVectorGeneratorType vectorGeneratorType;

    private final PaddingRecordGeneratorType recordGeneratorType;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private PaddingOracleTestInfo() {
        this.version = null;
        this.cipherSuite = null;
        this.vectorGeneratorType = null;
        this.recordGeneratorType = null;
    }

    public PaddingOracleTestInfo(
            ProtocolVersion version,
            CipherSuite suite,
            PaddingVectorGeneratorType vectorGeneratorType,
            PaddingRecordGeneratorType recordGeneratorType) {
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
        return vectorGeneratorType.name()
                + ":"
                + recordGeneratorType.name()
                + ":"
                + version.name()
                + ":"
                + cipherSuite.name();
    }

    @Override
    public List<String> getFieldNames() {
        return Arrays.asList(
                "Vector Generator Type", "Record Generator Type", "Version", "CipherSuite");
    }

    @Override
    public List<String> getFieldValues() {
        return Arrays.asList(vectorGeneratorType.name(), version.name(), cipherSuite.name());
    }

    @Override
    public String getPrintableName() {
        return vectorGeneratorType.name()
                + "\t"
                + recordGeneratorType.name()
                + "\t"
                + version.name()
                + "\t"
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
