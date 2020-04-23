/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.directRaccoon;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.report.after.statistic.nondeterminism.NondeterministicVectorContainerHolder;
import java.util.HashSet;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonCipherSuiteFingerprint {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;
    private final CipherSuite suite;
    private final DirectRaccoonWorkflowType workflowType;
    private final List<VectorResponse> responseMapList;
    private Boolean handshakeIsWorking;

    private final EqualityError equalityError;

    public DirectRaccoonCipherSuiteFingerprint(ProtocolVersion version, CipherSuite suite,
            DirectRaccoonWorkflowType workflowType, List<VectorResponse> responseMapList) {
        this.version = version;
        this.suite = suite;
        this.workflowType = workflowType;
        this.responseMapList = responseMapList;
        this.equalityError = evaluateEqualityError();
        handshakeIsWorking = null;
    }

    private EqualityError evaluateEqualityError() {
        for (VectorResponse vectorResponseOne : responseMapList) {
            for (VectorResponse vectorResponseTwo : responseMapList) {
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

    public void appendToResponseMap(List<VectorResponse> responseMap) {
        this.responseMapList.addAll(responseMap);
    }

    public Boolean getHandshakeIsWorking() {
        return handshakeIsWorking;
    }

    public void setHandshakeIsWorking(Boolean handshakeIsWorking) {
        this.handshakeIsWorking = handshakeIsWorking;
    }

    public List<VectorResponse> getResponseMapList() {
        return responseMapList;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getSuite() {
        return suite;
    }

    public EqualityError getEqualityError() {
        return equalityError;
    }

    public double getpValue() {
        return new NondeterministicVectorContainerHolder(responseMapList).computePValue();
    }

    public Boolean isConsideredVulnerable() {
        return this.getpValue() <= 0.05;
    }

    public DirectRaccoonWorkflowType getWorkflowType() {
        return workflowType;
    }

    public boolean isPotentiallyVulnerable() {
        HashSet<ResponseFingerprint> set = new HashSet<>();
        for (VectorResponse vectorResponse : responseMapList) {
            set.add(vectorResponse.getFingerprint());
        }
        return set.size() > 1;
    }
}
