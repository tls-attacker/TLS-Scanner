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
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.report.after.statistic.nondeterminism.NondeterministicVectorContainerHolder;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingOracleCipherSuiteFingerprint {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;
    private final CipherSuite suite;
    private final PaddingVectorGeneratorType vectorGeneratorType;
    private final PaddingRecordGeneratorType recordGeneratorType;
    private final List<VectorResponse> responseMap;

    private EqualityError equalityError;
    private double pValue;
    private Boolean consideredVulnerable;

    private PaddingOracleCipherSuiteFingerprint() {
        version = null;
        suite = null;
        vectorGeneratorType = null;
        recordGeneratorType = null;
        responseMap = null;
    }

    public PaddingOracleCipherSuiteFingerprint(ProtocolVersion version, CipherSuite suite,
            PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType recordGeneratorType,
            List<VectorResponse> responseMap, EqualityError equalityError, double pValue, Boolean consideredVulnerable) {
        this.version = version;
        this.suite = suite;
        this.vectorGeneratorType = vectorGeneratorType;
        this.recordGeneratorType = recordGeneratorType;
        this.responseMap = responseMap;
        this.pValue = pValue;
        this.consideredVulnerable = consideredVulnerable;
        this.equalityError = equalityError;
    }

    public List<VectorResponse> getResponseMap() {
        return Collections.unmodifiableList(responseMap);
    }

    public Boolean getConsideredVulnerable() {
        return consideredVulnerable;
    }

    public void setConsideredVulnerable(Boolean consideredVulnerable) {
        this.consideredVulnerable = consideredVulnerable;
    }

    public void appendToResponseMap(List<VectorResponse> responseMap) {
        this.responseMap.addAll(responseMap);
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

    public double getpValue() {
        return pValue;
    }

    public void setEqualityError(EqualityError equalityError) {
        this.equalityError = equalityError;
    }

    public void setpValue(double pValue) {
        this.pValue = pValue;
    }
}
