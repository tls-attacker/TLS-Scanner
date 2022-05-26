/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.cca.vector;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaCertificateType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaWorkflowType;

public class CcaVector {

    private final ProtocolVersion protocolVersion;
    private final CipherSuite cipherSuite;
    private final CcaWorkflowType ccaWorkflowType;
    private final CcaCertificateType ccaCertificateType;

    public CcaVector(ProtocolVersion protocolVersion, CipherSuite cipherSuite, CcaWorkflowType ccaWorkflowType,
        CcaCertificateType ccaCertificateType) {
        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
        this.ccaWorkflowType = ccaWorkflowType;
        this.ccaCertificateType = ccaCertificateType;
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public CcaWorkflowType getCcaWorkflowType() {
        return ccaWorkflowType;
    }

    public CcaCertificateType getCcaCertificateType() {
        return ccaCertificateType;
    }

    @Override
    public String toString() {
        return "CcaTask{protocolVersion=" + protocolVersion + ", cipherSuite=" + cipherSuite + ", workflowType="
            + ccaWorkflowType + ", certificateType=" + ccaCertificateType + "}";
    }

}
