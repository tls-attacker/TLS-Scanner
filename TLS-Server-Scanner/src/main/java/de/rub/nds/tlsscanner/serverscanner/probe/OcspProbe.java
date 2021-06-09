/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.OcspResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ocsp.OcspCertificateResult;
import java.math.BigInteger;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Nils Hanke - {@literal nils.hanke@rub.de}
 */
public class OcspProbe extends TlsProbe {

    private List<CertificateChain> serverCertChains;
    private List<NamedGroup> tls13NamedGroups;

    public static final int NONCE_TEST_VALUE_1 = 42;
    public static final int NONCE_TEST_VALUE_2 = 1337;
    private static final long STAPLED_NONCE_RANDOM_SEED = 42;
    private static final int STAPLED_NONCE_RANDOM_BIT_LENGTH = 128;

    public OcspProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.OCSP, config);
    }

    @Override
    public ProbeResult executeTest() {
        Config tlsConfig = initTlsConfig();
        List<OcspCertificateResult> ocspCertResults = new LinkedList<>();

        if (serverCertChains == null) {
            LOGGER.warn("Couldn't fetch certificate chains from server!");
            return getCouldNotExecuteResult();
        }

        for (CertificateChain serverCertChain : serverCertChains) {
            OcspCertificateResult certResult = new OcspCertificateResult(serverCertChain);

            getMustStaple(serverCertChain.getCertificate(), certResult);
            getStapledResponse(tlsConfig, certResult);
            performRequest(serverCertChain.getCertificate(), certResult);

            ocspCertResults.add(certResult);
        }
        List<CertificateStatusRequestExtensionMessage> tls13CertStatus = null;
        if (tls13NamedGroups != null) {
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
            LOGGER.warn("Couldn't determine OCSP must staple flag in certificate.");
        }
    }

    private void getStapledResponse(Config tlsConfig, OcspCertificateResult certResult) {
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
                LOGGER.warn("Tried parsing stapled OCSP message, but failed. Will be empty.");
            }
        }
    }

    private void performRequest(Certificate serverCertificateChain, OcspCertificateResult certResult) {
        try {
            CertificateInformationExtractor mainCertExtractor =
                new CertificateInformationExtractor(serverCertificateChain.getCertificateAt(0));
            URL ocspResponderUrl;

            // Check if leaf certificate supports OCSP
            try {
                ocspResponderUrl = new URL(mainCertExtractor.getOcspServerUrl());
                certResult.setSupportsOcsp(true);
            } catch (NoSuchFieldException ex) {
                LOGGER.debug(
                    "Cannot extract OCSP responder URL from leaf certificate. This certificate likely does not support OCSP.");
                certResult.setSupportsOcsp(false);
                return;
            } catch (Exception ex) {
                LOGGER.warn("Failed to extract OCSP responder URL from leaf certificate. Cannot make an OCSP request.");
                return;
            }

            OCSPRequest ocspRequest = new OCSPRequest(serverCertificateChain, ocspResponderUrl);

            // First Request Message with first fixed nonce test value
            OCSPRequestMessage ocspFirstRequestMessage = ocspRequest.createDefaultRequestMessage();
            ocspFirstRequestMessage.setNonce(new BigInteger(String.valueOf(NONCE_TEST_VALUE_1)));
            ocspFirstRequestMessage.addExtension(OCSPResponseTypes.NONCE.getOID());
            certResult.setFirstResponse(ocspRequest.makeRequest(ocspFirstRequestMessage));
            certResult.setHttpGetResponse(ocspRequest.makeGetRequest(ocspFirstRequestMessage));

            // If nonce is supported used, check if server actually replies
            // with a different one immediately after
            if (certResult.getFirstResponse().getNonce() != null) {
                certResult.setSupportsNonce(true);
                OCSPRequestMessage ocspSecondRequestMessage = ocspRequest.createDefaultRequestMessage();
                ocspSecondRequestMessage.setNonce(new BigInteger(String.valueOf(NONCE_TEST_VALUE_2)));
                ocspSecondRequestMessage.addExtension(OCSPResponseTypes.NONCE.getOID());
                certResult.setSecondResponse(ocspRequest.makeRequest(ocspSecondRequestMessage));
                LOGGER.debug(certResult.getSecondResponse().toString());
            } else {
                certResult.setSupportsNonce(false);
            }
        } catch (Exception e) {
            LOGGER.error("OCSP probe failed.");
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

    private Config initTlsConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

        tlsConfig.setCertificateStatusRequestExtensionRequestExtension(prepareNonceExtension());
        tlsConfig.setAddCertificateStatusRequestExtension(true);

        return tlsConfig;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        // We also need the tls13 groups to perform a tls13 handshake
        return report.getCertificateChainList() != null && !report.getCertificateChainList().isEmpty()
            && report.isProbeAlreadyExecuted(ProbeType.NAMED_GROUPS);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverCertChains = new LinkedList<>();
        for (CertificateChain chain : report.getCertificateChainList()) {
            serverCertChains.add(chain);
        }
        tls13NamedGroups = report.getSupportedTls13Groups();
    }

    private List<CertificateStatusRequestExtensionMessage> getCertificateStatusFromCertificateEntryExtension() {
        List<CertificateStatusRequestExtensionMessage> certificateStatuses = new LinkedList<>();
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplementedTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setDefaultClientNamedGroups(tls13NamedGroups);
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setDefaultClientKeyShareNamedGroups(tls13NamedGroups);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms());
        State state = new State(tlsConfig);
        List<PskKeyExchangeMode> pskKex = new LinkedList<>();
        pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
        pskKex.add(PskKeyExchangeMode.PSK_KE);
        tlsConfig.setPSKKeyExchangeModes(pskKex);
        tlsConfig.setAddPSKKeyExchangeModesExtension(true);
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
    public ProbeResult getCouldNotExecuteResult() {
        return new OcspResult(null, null);
    }
}
