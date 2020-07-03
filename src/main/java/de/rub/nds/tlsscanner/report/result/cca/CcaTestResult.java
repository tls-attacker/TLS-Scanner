/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result.cca;

import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

public class CcaTestResult {

    private final Boolean succeeded;
    private final CcaWorkflowType workflowType;
    private final CcaCertificateType certificateType;
    private final ProtocolVersion protocolVersion;
    private final CipherSuite cipherSuite;

    public CcaTestResult(Boolean succeeded, CcaWorkflowType workflowType, CcaCertificateType certificateType,
            ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        this.succeeded = succeeded;
        this.workflowType = workflowType;
        this.certificateType = certificateType;
        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
    }

    public Boolean getSucceeded() {
        return succeeded;
    }

    public CcaWorkflowType getWorkflowType() {
        return workflowType;
    }

    public CcaCertificateType getCertificateType() {
        return certificateType;
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }
}