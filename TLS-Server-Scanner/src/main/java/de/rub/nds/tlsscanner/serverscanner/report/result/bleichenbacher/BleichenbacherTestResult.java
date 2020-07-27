/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result.bleichenbacher;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import java.util.List;

/**
 *
 * @author robert
 */
public class BleichenbacherTestResult {

    private final Boolean vulnerable;
    private final BleichenbacherCommandConfig.Type scanDetail;
    private final BleichenbacherWorkflowType workflowType;

    private final List<VectorResponse> vectorFingerPrintPairList;

    private final EqualityError equalityError;

    private BleichenbacherTestResult() {
        vulnerable = null;
        scanDetail = null;
        workflowType = null;
        vectorFingerPrintPairList = null;
        equalityError = null;
    }

    public BleichenbacherTestResult(Boolean vulnerable, BleichenbacherCommandConfig.Type scanDetail,
            BleichenbacherWorkflowType workflowType, List<VectorResponse> vectorFingerPrintPairList,
            EqualityError equalityError) {
        this.vulnerable = vulnerable;
        this.scanDetail = scanDetail;
        this.workflowType = workflowType;
        this.vectorFingerPrintPairList = vectorFingerPrintPairList;
        this.equalityError = equalityError;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public BleichenbacherCommandConfig.Type getScanDetail() {
        return scanDetail;
    }

    public BleichenbacherWorkflowType getWorkflowType() {
        return workflowType;
    }

    public List<VectorResponse> getVectorFingerPrintPairList() {
        return vectorFingerPrintPairList;
    }

    public EqualityError getEqualityError() {
        return equalityError;
    }

}
