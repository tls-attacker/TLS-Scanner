/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.probe.invalidCurve;

import de.rub.nds.tlsattacker.attacks.util.response.FingerprintSecretPair;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsscanner.rating.TestResult;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class InvalidCurveResponse {
    private InvalidCurveParameterSet parameterSet;
    private List<FingerprintSecretPair> fingerprintSecretPairs;
    private List<Point> receivedEcPublicKeys;
    private List<Point> receivedFinishedEcKeys;
    private TestResult showsPointsAreNotValidated = TestResult.NOT_TESTED_YET;
    private TestResult showsVulnerability = TestResult.NOT_TESTED_YET;
    private TestResult chosenGroupReusesKey = TestResult.NOT_TESTED_YET;
    
    private TestResult finishedHandshakeHadReusedKey = TestResult.FALSE;
    private TestResult dirtyKeysWarning = TestResult.FALSE;

    public InvalidCurveResponse(InvalidCurveParameterSet parameterSet, List<FingerprintSecretPair> fingerprintSecretPairs,
            TestResult showsPointsAreNotValidated, List<Point> receivedEcPublicKeys, List<Point> receivedFinishedEcKeys, TestResult dirtyKeysWarning) {
        this.parameterSet = parameterSet;
        this.fingerprintSecretPairs = fingerprintSecretPairs;
        this.showsPointsAreNotValidated = showsPointsAreNotValidated;
        this.receivedEcPublicKeys = receivedEcPublicKeys;
        this.receivedFinishedEcKeys = receivedFinishedEcKeys;
        this.dirtyKeysWarning = dirtyKeysWarning;
    }

    public InvalidCurveResponse(InvalidCurveParameterSet parameterSet, TestResult showsPointsAreNotValidated) {
        this.parameterSet = parameterSet;
        this.showsPointsAreNotValidated = showsPointsAreNotValidated;
        this.fingerprintSecretPairs = new LinkedList<>();
        this.receivedEcPublicKeys = new LinkedList<>();
    }

    /**
     * @return the parameterSet
     */
    public InvalidCurveParameterSet getParameterSet() {
        return parameterSet;
    }
    
    /**
     * @return the showsPointsAreNotValidated
     */
    public TestResult getShowsPointsAreNotValidated() {
        return showsPointsAreNotValidated;
    }

    /**
     * @param showsPointsAreNotValidated
     *            the showsPointsAreNotValidated to set
     */
    public void setShowsPointsAreNotValuated(TestResult showsPointsAreNotValidated) {
        this.showsPointsAreNotValidated = showsPointsAreNotValidated;
    }

    /**
     * @return the showsVulnerability
     */
    public TestResult getShowsVulnerability() {
        return showsVulnerability;
    }

    /**
     * @param showsVulnerability
     *            the showsVulnerability to set
     */
    public void setShowsVulnerability(TestResult showsVulnerability) {
        this.showsVulnerability = showsVulnerability;
    }

    /**
     * @return the chosenGroupReusesKey
     */
    public TestResult getChosenGroupReusesKey() {
        return chosenGroupReusesKey;
    }

    /**
     * @param chosenGroupReusesKey
     *            the chosenGroupReusesKey to set
     */
    public void setChosenGroupReusesKey(TestResult chosenGroupReusesKey) {
        this.chosenGroupReusesKey = chosenGroupReusesKey;
    }

    /**
     * @return the receivedEcPublicKeys
     */
    public List<Point> getReceivedEcPublicKeys() {
        return receivedEcPublicKeys;
    }

    /**
     * @param receivedEcPublicKeys
     *            the receivedEcPublicKeys to set
     */
    public void setReceivedEcPublicKeys(List<Point> receivedEcPublicKeys) {
        this.receivedEcPublicKeys = receivedEcPublicKeys;
    }

    /**
     * @return the fingerprintSecretPairs
     */
    public List<FingerprintSecretPair> getFingerprintSecretPairs() {
        return fingerprintSecretPairs;
    }

    /**
     * @param fingerprintSecretPairs the fingerprintSecretPairs to set
     */
    public void setFingerprintSecretPairs(List<FingerprintSecretPair> fingerprintSecretPairs) {
        this.fingerprintSecretPairs = fingerprintSecretPairs;
    }

    /**
     * @return the finishedHandshakeHadReusedKey
     */
    public TestResult getFinishedHandshakeHadReusedKey() {
        return finishedHandshakeHadReusedKey;
    }

    /**
     * @param finishedHandshakeHadReusedKey the finishedHandshakeHadReusedKey to set
     */
    public void setFinishedHandshakeHadReusedKey(TestResult finishedHandshakeHadReusedKey) {
        this.finishedHandshakeHadReusedKey = finishedHandshakeHadReusedKey;
    }

    /**
     * @return the receivedFinishedEcKeys
     */
    public List<Point> getReceivedFinishedEcKeys() {
        return receivedFinishedEcKeys;
    }

    /**
     * @param receivedFinishedEcKeys the receivedFinishedEcKeys to set
     */
    public void setReceivedFinishedEcKeys(List<Point> receivedFinishedEcKeys) {
        this.receivedFinishedEcKeys = receivedFinishedEcKeys;
    }

    /**
     * @return the dirtyKeysWarning
     */
    public TestResult getDirtyKeysWarning() {
        return dirtyKeysWarning;
    }

    /**
     * @param dirtyKeysWarning the dirtyKeysWarning to set
     */
    public void setDirtyKeysWarning(TestResult dirtyKeysWarning) {
        this.dirtyKeysWarning = dirtyKeysWarning;
    }

}
