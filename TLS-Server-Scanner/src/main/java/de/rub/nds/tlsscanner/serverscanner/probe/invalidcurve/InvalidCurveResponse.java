/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.FingerprintSecretPair;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class InvalidCurveResponse {

    private InvalidCurveVector vector;
    private List<FingerprintSecretPair> fingerprintSecretPairs;
    private List<Point> receivedEcPublicKeys;
    private List<Point> receivedFinishedEcKeys;
    private TestResult showsPointsAreNotValidated = TestResult.NOT_TESTED_YET;
    private TestResult showsVulnerability = TestResult.NOT_TESTED_YET;
    private TestResult chosenGroupReusesKey = TestResult.NOT_TESTED_YET;

    private TestResult finishedHandshakeHadReusedKey = TestResult.FALSE;
    private TestResult dirtyKeysWarning = TestResult.FALSE;

    private TestResult sideChannelSuspected = TestResult.FALSE;
    private TestResult hadDistinctFps = TestResult.FALSE;
    private InvalidCurveScanType scanType = InvalidCurveScanType.REGULAR;

    private InvalidCurveResponse() {
    }

    public InvalidCurveResponse(InvalidCurveVector parameterSet, List<FingerprintSecretPair> fingerprintSecretPairs,
        TestResult showsPointsAreNotValidated, List<Point> receivedEcPublicKeys, List<Point> receivedFinishedEcKeys,
        TestResult dirtyKeysWarning, InvalidCurveScanType scanType) {
        this.vector = parameterSet;
        this.fingerprintSecretPairs = fingerprintSecretPairs;
        this.showsPointsAreNotValidated = showsPointsAreNotValidated;
        this.receivedEcPublicKeys = receivedEcPublicKeys;
        this.receivedFinishedEcKeys = receivedFinishedEcKeys;
        this.dirtyKeysWarning = dirtyKeysWarning;
        this.scanType = scanType;
    }

    public InvalidCurveResponse(InvalidCurveVector parameterSet, TestResult showsPointsAreNotValidated) {
        this.vector = parameterSet;
        this.showsPointsAreNotValidated = showsPointsAreNotValidated;
        this.fingerprintSecretPairs = new LinkedList<>();
        this.receivedEcPublicKeys = new LinkedList<>();
    }

    /**
     * @return the parameterSet
     */
    public InvalidCurveVector getVector() {
        return vector;
    }

    /**
     * @return the showsPointsAreNotValidated
     */
    public TestResult getShowsPointsAreNotValidated() {
        return showsPointsAreNotValidated;
    }

    /**
     * @param showsPointsAreNotValidated
     *                                   the showsPointsAreNotValidated to set
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
     *                           the showsVulnerability to set
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
     *                             the chosenGroupReusesKey to set
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
     *                             the receivedEcPublicKeys to set
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
     * @param fingerprintSecretPairs
     *                               the fingerprintSecretPairs to set
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
     * @param finishedHandshakeHadReusedKey
     *                                      the finishedHandshakeHadReusedKey to set
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
     * @param receivedFinishedEcKeys
     *                               the receivedFinishedEcKeys to set
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
     * @param dirtyKeysWarning
     *                         the dirtyKeysWarning to set
     */
    public void setDirtyKeysWarning(TestResult dirtyKeysWarning) {
        this.dirtyKeysWarning = dirtyKeysWarning;
    }

    public void mergeResponse(InvalidCurveResponse toMerge) {
        fingerprintSecretPairs.addAll(toMerge.getFingerprintSecretPairs());
        receivedEcPublicKeys.addAll(toMerge.getReceivedEcPublicKeys());
        receivedFinishedEcKeys.addAll(toMerge.getReceivedFinishedEcKeys());

        if (toMerge.getShowsPointsAreNotValidated() == TestResult.TRUE) {
            showsPointsAreNotValidated = TestResult.TRUE;
        }
        if (toMerge.getShowsVulnerability() == TestResult.TRUE) {
            showsVulnerability = TestResult.TRUE;
        }
        if (toMerge.getChosenGroupReusesKey() == TestResult.TRUE) {
            chosenGroupReusesKey = TestResult.TRUE;
        }
        if (toMerge.getFinishedHandshakeHadReusedKey() == TestResult.TRUE) {
            finishedHandshakeHadReusedKey = TestResult.TRUE;
        }
        if (toMerge.getDirtyKeysWarning() == TestResult.TRUE) {
            dirtyKeysWarning = TestResult.TRUE;
        }

        setScanType(toMerge.getScanType());
    }

    public List<VectorResponse> getVectorResponses() {
        List<VectorResponse> responses = new LinkedList<>();
        for (FingerprintSecretPair pair : fingerprintSecretPairs) {
            if (pair.getFingerprint() != null) {
                responses.add(new VectorResponse(vector, pair.getFingerprint()));
            }
        }
        return responses;
    }

    public TestResult getSideChannelSuspected() {
        return sideChannelSuspected;
    }

    public void setSideChannelSuspected(TestResult sideChannelSuspected) {
        this.sideChannelSuspected = sideChannelSuspected;
    }

    public TestResult getHadDistinctFps() {
        return hadDistinctFps;
    }

    public void setHadDistinctFps(TestResult hadDistinctFps) {
        this.hadDistinctFps = hadDistinctFps;
    }

    public InvalidCurveScanType getScanType() {
        return scanType;
    }

    public void setScanType(InvalidCurveScanType scanType) {
        this.scanType = scanType;
    }

}
