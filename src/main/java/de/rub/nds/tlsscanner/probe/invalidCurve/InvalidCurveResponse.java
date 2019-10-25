/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.probe.invalidCurve;

import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsscanner.rating.TestResult;
import java.util.List;

/**
 *
 */
public class InvalidCurveResponse {
    private InvalidCurveParameterSet parameterSet;
    private List<ResponseFingerprint> responseFingerprints;
    private List<Point> receivedEcPublicKeys;
    private TestResult showsPointsAreNotValidated = TestResult.NOT_TESTED_YET;
    private TestResult showsVulnerability = TestResult.NOT_TESTED_YET;
    private TestResult chosenGroupReusesKey = TestResult.NOT_TESTED_YET;
    
    public InvalidCurveResponse(InvalidCurveParameterSet parameterSet, List<ResponseFingerprint> responseFingerprints, TestResult showsPointsAreNotValidated, List<Point> receivedEcPublicKeys)
    {
        this.parameterSet = parameterSet;
        this.responseFingerprints = responseFingerprints;
        this.showsPointsAreNotValidated = showsPointsAreNotValidated;
        this.receivedEcPublicKeys = receivedEcPublicKeys;
    }

    /**
     * @return the parameterSet
     */
    public InvalidCurveParameterSet getParameterSet() {
        return parameterSet;
    }

    /**
     * @return the responseFingerprints
     */
    public List<ResponseFingerprint> getResponseFingerprints() {
        return responseFingerprints;
    }

    /**
     * @return the showsPointsAreNotValidated
     */
    public TestResult getShowsPointsAreNotValidated() {
        return showsPointsAreNotValidated;
    }

    /**
     * @param showsPointsAreNotValidated the showsPointsAreNotValidated to set
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
     * @param showsVulnerability the showsVulnerability to set
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
     * @param chosenGroupReusesKey the chosenGroupReusesKey to set
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
     * @param receivedEcPublicKeys the receivedEcPublicKeys to set
     */
    public void setReceivedEcPublicKeys(List<Point> receivedEcPublicKeys) {
        this.receivedEcPublicKeys = receivedEcPublicKeys;
    }
    
    
}
