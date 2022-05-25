/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.NONCE;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateInformationExtractor;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPRequest;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPRequestMessage;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseParser;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.result.OcspResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.ocsp.OcspCertificateResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.bouncycastle.crypto.tls.Certificate;

public class OcspProbe extends TlsServerProbe<ConfigSelector, ServerReport, OcspResult> {

    private List<CertificateChain> serverCertChains;
    private List<NamedGroup> tls13NamedGroups;

    public static final int NONCE_TEST_VALUE_1 = 42;
    public static final int NONCE_TEST_VALUE_2 = 1337;
    private static final long STAPLED_NONCE_RANDOM_SEED = 42;
    private static final int STAPLED_NONCE_RANDOM_BIT_LENGTH = 128;

    public OcspProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.OCSP, configSelector);
    }

    @Override
    public OcspResult executeTest() {
        List<OcspCertificateResult> ocspCertResults = new LinkedList<>();
        for (CertificateChain serverCertChain : serverCertChains) {
            OcspCertificateResult certResult = new OcspCertificateResult(serverCertChain);

            getMustStaple(serverCertChain.getCertificate(), certResult);
            getStapledResponse(certResult);
            performRequest(serverCertChain.getCertificate(), certResult);

            ocspCertResults.add(certResult);
        }
        List<CertificateStatusRequestExtensionMessage> tls13CertStatus = null;
        if (!tls13NamedGroups.isEmpty()) {
            tls13CertStatus = getCertificateStatusFromCertificateEntryExtension();
        }
        return new OcspResult(ocspCertResults, tls13CertStatus);
    }

    private void getMustStaple(Certificate certChain, OcspCertificateResult certResult) {
        org.bouncycastle.asn1.x509.Certificate singleCert = certChain.getCertificateAt(0);
        CertificateInformationExtractor certInformationExtractor = new CertificateInformationExtractor(singleCert);
        try {
            certResult.setMustStaple(certInformationExtractor.getMustStaple());
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
            } else {
                LOGGER.warn("Couldn't determine OCSP must staple flag in certificate.");
            }
        }
    }

    private void getStapledResponse(OcspCertificateResult certResult) {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setCertificateStatusRequestExtensionRequestExtension(prepareNonceExtension());
        tlsConfig.setAddCertificateStatusRequestExtension(true);

        State state = new State(tlsConfig);
        executeState(state);
        List<ExtensionType> supportedExtensions = new ArrayList<>(state.getTlsContext().getNegotiatedExtensionSet());

        CertificateStatusMessage certificateStatusMessage = null;
        if (supportedExtensions.contains(ExtensionType.STATUS_REQUEST)) {
            certResult.setSupportsStapling(true);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_STATUS,
                state.getWorkflowTrace())) {
                certificateStatusMessage = (CertificateStatusMessage) WorkflowTraceUtil
                    .getFirstReceivedMessage(HandshakeMessageType.CERTIFICATE_STATUS, state.getWorkflowTrace());
            }
        } else {
            certResult.setSupportsStapling(false);
        }

        if (certificateStatusMessage != null) {
            try {
                certResult.setStapledResponse(
                    OCSPResponseParser.parseResponse(certificateStatusMessage.getOcspResponseBytes().getValue()));
            } catch (Exception e) {
                if (e.getCause() instanceof InterruptedException) {
                    LOGGER.error("Timeout on " + getProbeName());
                } else {
                    LOGGER.warn("Tried parsing stapled OCSP message, but failed. Will be empty.");
                }
            }
        }
    }

    private void performRequest(Certificate serverCertificateChain, OcspCertificateResult certResult) {
        CertificateInformationExtractor mainCertExtractor =
            new CertificateInformationExtractor(serverCertificateChain.getCertificateAt(0));
        URL ocspResponderUrl;

        try {
            // Check if leaf certificate supports OCSP
            ocspResponderUrl = new URL(mainCertExtractor.getOcspServerUrl());
        } catch (MalformedURLException ex) {
            throw new RuntimeException(ex);
        }
        certResult.setSupportsOcsp(true);

        OCSPRequest ocspRequest = new OCSPRequest(serverCertificateChain, ocspResponderUrl);

        // First Request Message with first fixed nonce test value
        OCSPRequestMessage ocspFirstRequestMessage = ocspRequest.createDefaultRequestMessage();
        ocspFirstRequestMessage.setNonce(new BigInteger(String.valueOf(NONCE_TEST_VALUE_1)));
        ocspFirstRequestMessage.addExtension(OCSPResponseTypes.NONCE.getOID());
        certResult.setFirstResponse(ocspRequest.makeRequest(ocspFirstRequestMessage));
        certResult.setHttpGetResponse(ocspRequest.makeGetRequest(ocspFirstRequestMessage));

        // If nonce is supported used, check if server actually replies
        // with a different one immediately after
        if (certResult.getFirstResponse() != null && certResult.getFirstResponse().getNonce() != null) {
            certResult.setSupportsNonce(true);
            OCSPRequestMessage ocspSecondRequestMessage = ocspRequest.createDefaultRequestMessage();
            ocspSecondRequestMessage.setNonce(new BigInteger(String.valueOf(NONCE_TEST_VALUE_2)));
            ocspSecondRequestMessage.addExtension(OCSPResponseTypes.NONCE.getOID());
            certResult.setSecondResponse(ocspRequest.makeRequest(ocspSecondRequestMessage));
            LOGGER.debug(certResult.getSecondResponse().toString());
        } else {
            certResult.setSupportsNonce(false);
        }
    }

    private byte[] prepareNonceExtension() {
        Asn1Sequence innerExtensionSequence = new Asn1Sequence();
        Asn1ObjectIdentifier oid = new Asn1ObjectIdentifier();
        oid.setValue(NONCE.getOID());

        Asn1Sequence extensionSequence = new Asn1Sequence();
        innerExtensionSequence.addChild(oid);

        Asn1EncapsulatingOctetString encapsulatingOctetString = new Asn1EncapsulatingOctetString();

        // Nonce
        Asn1PrimitiveOctetString nonceOctetString = new Asn1PrimitiveOctetString();

        Random rand = new Random(STAPLED_NONCE_RANDOM_SEED);
        BigInteger nonce = new BigInteger(STAPLED_NONCE_RANDOM_BIT_LENGTH, rand);

        nonceOctetString.setValue(nonce.toByteArray());
        encapsulatingOctetString.addChild(nonceOctetString);

        innerExtensionSequence.addChild(encapsulatingOctetString);
        extensionSequence.addChild(innerExtensionSequence);

        List<Asn1Encodable> asn1Encodables = new LinkedList<>();
        asn1Encodables.add(extensionSequence);

        Asn1Encoder asn1Encoder = new Asn1Encoder(asn1Encodables);
        return asn1Encoder.encode();
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        // We also need the tls13 groups to perform a tls13 handshake
        return report.getCertificateChainList() != null && !report.getCertificateChainList().isEmpty()
            && report.isProbeAlreadyExecuted(TlsProbeType.NAMED_GROUPS);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        serverCertChains = new LinkedList<>();
        for (CertificateChain chain : report.getCertificateChainList()) {
            serverCertChains.add(chain);
        }
        tls13NamedGroups = report.getSupportedTls13Groups();
    }

    private List<CertificateStatusRequestExtensionMessage> getCertificateStatusFromCertificateEntryExtension() {
        List<CertificateStatusRequestExtensionMessage> certificateStatuses = new LinkedList<>();
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        List<PskKeyExchangeMode> pskKex = new LinkedList<>();
        pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
        pskKex.add(PskKeyExchangeMode.PSK_KE);
        tlsConfig.setPSKKeyExchangeModes(pskKex);
        tlsConfig.setAddPSKKeyExchangeModesExtension(true);

        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace())) {
            CertificateMessage certificateMessage = (CertificateMessage) WorkflowTraceUtil
                .getFirstReceivedMessage(HandshakeMessageType.CERTIFICATE, state.getWorkflowTrace());
            List<CertificateEntry> certificateEntries = certificateMessage.getCertificatesListAsEntry();
            for (CertificateEntry certificateEntry : certificateEntries) {
                for (ExtensionMessage extensionMessage : certificateEntry.getExtensions()) {
                    if (extensionMessage instanceof CertificateStatusRequestExtensionMessage) {
                        certificateStatuses.add((CertificateStatusRequestExtensionMessage) extensionMessage);
                    }
                }
            }
        }
        return certificateStatuses;
    }

    @Override
    public OcspResult getCouldNotExecuteResult() {
        return new OcspResult(null, null);
    }
}
