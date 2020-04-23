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

    public PaddingOracleCipherSuiteFingerprint(ProtocolVersion version, CipherSuite suite,
            PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType recordGeneratorType,
            List<VectorResponse> responseMap) {
        this.version = version;
        this.suite = suite;
        this.vectorGeneratorType = vectorGeneratorType;
        this.recordGeneratorType = recordGeneratorType;
        this.responseMap = responseMap;
        pValue = computePValue();
        equalityError = evaluateEqualityError();
    }

    public List<VectorResponse> getResponseMap() {
        return Collections.unmodifiableList(responseMap);
    }

    public void appendToResponseMap(List<VectorResponse> responseMap) {
        this.responseMap.addAll(responseMap);
        pValue = computePValue();
        equalityError = evaluateEqualityError();
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

    private EqualityError evaluateEqualityError() {
        for (VectorResponse vectorResponseOne : responseMap) {
            for (VectorResponse vectorResponseTwo : responseMap) {
                if (vectorResponseOne == vectorResponseTwo) {
                    continue;
                }
                EqualityError equality = FingerPrintChecker.checkEquality(vectorResponseOne.getFingerprint(),
                        vectorResponseTwo.getFingerprint(), true);
                if (equality != EqualityError.NONE) {
                    return equality;
                }
            }
        }
        return EqualityError.NONE;
    }

    private double computePValue() {
        NondeterministicVectorContainerHolder holder = new NondeterministicVectorContainerHolder(responseMap);
        return holder.computePValue();
    }

    public boolean isConsideredVulnerable(double pValueThreshhold) {
        return (pValueThreshhold > this.pValue);
    }

    public boolean isConsideredVulnerable() {
        return this.pValue < 0.01d;
    }

}
