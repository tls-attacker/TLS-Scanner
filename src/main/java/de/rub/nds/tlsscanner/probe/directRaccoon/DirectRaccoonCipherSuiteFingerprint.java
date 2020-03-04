/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.directRaccoon;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsattacker.attacks.impl.FisherExactTest;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonCipherSuiteFingerprint {

    private static final Logger LOGGER = LogManager.getLogger();
    
    private final Boolean vulnerable;
    private final ProtocolVersion version;
    private final CipherSuite suite;
    private final DirectRaccoonWorkflowType workflowType;
    private final List<DirectRaccoonVectorResponse> responseMapList;
    private Boolean handshakeIsWorking;

    private final EqualityError equalityError;
    private final boolean hasScanningError;

    public DirectRaccoonCipherSuiteFingerprint(Boolean vulnerable, ProtocolVersion version, CipherSuite suite, DirectRaccoonWorkflowType workflowType, List<DirectRaccoonVectorResponse> responseMapList, EqualityError equalityError, boolean hasScanningError) {
        this.vulnerable = vulnerable;
        this.version = version;
        this.suite = suite;
        this.workflowType = workflowType;
        this.responseMapList = responseMapList;
        this.equalityError = equalityError;
        this.hasScanningError = hasScanningError;
        handshakeIsWorking = null;
    }

    public Boolean getHandshakeIsWorking() {
        return handshakeIsWorking;
    }

    public void setHandshakeIsWorking(Boolean handshakeIsWorking) {
        this.handshakeIsWorking = handshakeIsWorking;
    }

    public boolean isHasScanningError() {
        return hasScanningError;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public List<DirectRaccoonVectorResponse> getResponseMapList() {
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
    
    private double getFisherTestPValue(List<VectorResponse> responseVectorList) {
        // TODO: Make sure Vector and ResponseFingerprint implement hashCode().
        HashSet<Vector> vectors = new HashSet<>();
        HashSet<ResponseFingerprint> responseFingerprints = new HashSet<>();
        HashMap<Map.Entry<Vector, ResponseFingerprint>, Integer> contingencyTable = new HashMap<>();
        for (VectorResponse vectorResponse : responseVectorList) {
            Vector vector = vectorResponse.getVector();
            ResponseFingerprint fingerprint = vectorResponse.getFingerprint();
            vectors.add(vector);
            responseFingerprints.add(fingerprint);
            AbstractMap.SimpleEntry<Vector, ResponseFingerprint> entry = new java.util.AbstractMap.SimpleEntry<>(vector,
                    fingerprint);
            contingencyTable.put(entry, 1 + contingencyTable.getOrDefault(entry, 0));
        }
        if (vectors.size() != 2) {
            LOGGER.error("More than 2 vectors in Fisher test.");
            return 0;
        }
        if (responseFingerprints.size() != 2) {
            LOGGER.error("More than 2 responses in Fisher test.");
            return 0;
        }
        Vector vectorA = (Vector) vectors.toArray()[0];
        Vector vectorB = (Vector) vectors.toArray()[1];
        ResponseFingerprint response1 = (ResponseFingerprint) responseFingerprints.toArray()[0];
        ResponseFingerprint response2 = (ResponseFingerprint) responseFingerprints.toArray()[1];
        int inputAOutput1 = contingencyTable.get(new java.util.AbstractMap.SimpleEntry<>(vectorA, response1));
        int inputAOutput2 = contingencyTable.get(new java.util.AbstractMap.SimpleEntry<>(vectorA, response2));
        int inputBOutput1 = contingencyTable.get(new java.util.AbstractMap.SimpleEntry<>(vectorB, response1));
        int inputBOutput2 = contingencyTable.get(new java.util.AbstractMap.SimpleEntry<>(vectorB, response2));
        return FisherExactTest.getLog2PValue(inputAOutput1, inputBOutput1, inputAOutput2, inputBOutput2);
    }
}
