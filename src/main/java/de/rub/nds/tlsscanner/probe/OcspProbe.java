/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPRequest;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPRequestMessage;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponse;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseParser;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.OcspResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import org.bouncycastle.crypto.tls.Certificate;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Nils Hanke - nils.hanke@rub.de
 */
public class OcspProbe extends TlsProbe {

    private Boolean supportsStapling;
    private Boolean supportsNonce;
    private OCSPResponse stapledResponse;
    private OCSPResponse firstResponse;
    private OCSPResponse secondResponse;

    public OcspProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.OCSP, config, 0);
    }

    @Override
    public ProbeResult executeTest() {
        Config tlsConfig = initTlsConfig();
        Certificate serverCertChain = CertificateFetcher.fetchServerCertificate(tlsConfig);

        getStapledResponse(tlsConfig);

        if (serverCertChain == null) {
            LOGGER.error("Couldn't fetch certificate chain from server!");
            return new OcspResult(false, false, null, null, null);
        }

        try {
            OCSPRequest ocspRequest = new OCSPRequest(serverCertChain);

            // First Request Message with '42' as nonce
            OCSPRequestMessage ocspFirstRequestMessage = ocspRequest.createDefaultRequestMessage();
            ocspFirstRequestMessage.setNonce(new BigInteger("42"));
            ocspFirstRequestMessage.addExtension(OCSPResponseTypes.NONCE.getOID());
            firstResponse = ocspRequest.makeRequest(ocspFirstRequestMessage);

            // If nonce is supported used, check if server actually replies
            // with a different one immediately after
            if (firstResponse.getNonce() != null) {
                supportsNonce = true;
                OCSPRequestMessage ocspSecondRequestMessage = ocspRequest.createDefaultRequestMessage();
                ocspSecondRequestMessage.setNonce(new BigInteger("1337"));
                ocspSecondRequestMessage.addExtension(OCSPResponseTypes.NONCE.getOID());
                secondResponse = ocspRequest.makeRequest(ocspSecondRequestMessage);
                LOGGER.debug(secondResponse.toString());
            } else {
                supportsNonce = false;
            }
        } catch (Exception e) {
            LOGGER.error("OCSP Request/Response failed.");
        }

        return new OcspResult(supportsStapling, supportsNonce, stapledResponse, firstResponse, secondResponse);
    }

    private void getStapledResponse(Config tlsConfig) {
        State state = new State(tlsConfig);
        executeState(state);
        ArrayList supportedExtensions = new ArrayList(state.getTlsContext().getNegotiatedExtensionSet());

        CertificateStatusMessage certificateStatusMessage = null;
        if (supportedExtensions.contains(ExtensionType.STATUS_REQUEST)) {
            supportsStapling = true;
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_STATUS, state.getWorkflowTrace())) {
                certificateStatusMessage = (CertificateStatusMessage) WorkflowTraceUtil.getFirstReceivedMessage(
                        HandshakeMessageType.CERTIFICATE_STATUS, state.getWorkflowTrace());
            }
        } else {
            supportsStapling = false;
        }

        if (certificateStatusMessage != null) {
            try {
                stapledResponse = OCSPResponseParser.parseResponse(certificateStatusMessage.getOcspResponseBytes()
                        .getValue());
            } catch (Exception e) {
                LOGGER.error("Tried parsing stapled OCSP message, but failed. Will be empty.");
            }
        }
    }

    private Config initTlsConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);

        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        List<NamedGroup> namedGroups = Arrays.asList(NamedGroup.values());
        tlsConfig.setDefaultClientNamedGroups(namedGroups);
        List<SignatureAndHashAlgorithm> sigHashAlgos = Arrays.asList(SignatureAndHashAlgorithm.values());
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(sigHashAlgos);
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setDefaultClientSupportedCiphersuites(toTestList);
        tlsConfig.setStopActionsAfterFatal(true);
        return tlsConfig;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new OcspResult(false, false, null, null, null);
    }
}
