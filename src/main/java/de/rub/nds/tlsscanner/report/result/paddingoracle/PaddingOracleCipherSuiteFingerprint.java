/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result.paddingoracle;

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;

public class PaddingOracleCipherSuiteFingerprint {

    private final Boolean vulnerable;
    private final ProtocolVersion version;
    private final CipherSuite suite;
    private final PaddingVectorGeneratorType vectorGeneratorType;
    private final PaddingRecordGeneratorType recordGeneratorType;
    private final List<List<VectorResponse>> responseMapList;

    private final EqualityError equalityError;
    private final boolean shakyScans;
    private final boolean hasScanningError;

    public PaddingOracleCipherSuiteFingerprint(Boolean vulnerable, ProtocolVersion version, CipherSuite suite, PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType recordGeneratorType, List<List<VectorResponse>> responseMapList, EqualityError equalityError, boolean shakyScans, boolean hasScanningError) {
        this.vulnerable = vulnerable;
        this.version = version;
        this.suite = suite;
        this.vectorGeneratorType = vectorGeneratorType;
        this.recordGeneratorType = recordGeneratorType;
        this.responseMapList = responseMapList;
        this.equalityError = equalityError;
        this.shakyScans = shakyScans;
        this.hasScanningError = hasScanningError;
    }

    public boolean isShakyScans() {
        return shakyScans;
    }

    public boolean isHasScanningError() {
        return hasScanningError;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public List<List<VectorResponse>> getResponseMapList() {
        return responseMapList;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getSuite() {
        return suite;
    }

    public PaddingVectorGeneratorType getVectorGeneratorType() {
        return vectorGeneratorType;
    }

    public PaddingRecordGeneratorType getRecordGeneratorType() {
        return recordGeneratorType;
    }

    public EqualityError getEqualityError() {
        return equalityError;
    }
}
