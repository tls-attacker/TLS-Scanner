/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateInformationExtractor;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPRequest;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPRequestMessage;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponse;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseParser;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.NONCE;

/**
 *
 * @author Nils Hanke - nils.hanke@rub.de
 */
public class OcspProbe extends TlsProbe {

    private Boolean supportsOcsp;
    private boolean supportsStapling;
    private boolean mustStaple;
    private boolean supportsNonce;
    private OCSPResponse stapledResponse;
    private OCSPResponse firstResponse;
    private OCSPResponse secondResponse;

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
        Certificate serverCertChain = CertificateFetcher.fetchServerCertificate(tlsConfig);

        if (serverCertChain == null) {
            LOGGER.error("Couldn't fetch certificate chain from server!");
            return getCouldNotExecuteResult();
        }

        getMustStaple(serverCertChain);
        getStapledResponse(tlsConfig);
        performRequest(serverCertChain);

        return new OcspResult(supportsOcsp, supportsStapling, mustStaple, supportsNonce, stapledResponse,
                firstResponse, secondResponse);
    }

    private void getMustStaple(Certificate certChain) {
        org.bouncycastle.asn1.x509.Certificate singleCert = certChain.getCertificateAt(0);
        CertificateInformationExtractor certInformationExtractor = new CertificateInformationExtractor(singleCert);
        try {
            mustStaple = certInformationExtractor.getMustStaple();
        } catch (Exception e) {
            LOGGER.warn("Couldn't determine OCSP must staple flag in certificate.");
        }
    }

    private void getStapledResponse(Config tlsConfig) {
        State state = new State(tlsConfig);
        executeState(state);
        List<ExtensionType> supportedExtensions = new ArrayList<>(state.getTlsContext().getNegotiatedExtensionSet());

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

    private void performRequest(Certificate serverCertificateChain) {
        try {
            CertificateInformationExtractor mainCertExtractor = new CertificateInformationExtractor(
                    serverCertificateChain.getCertificateAt(0));
            URL ocspResponderUrl;

            // Check if leaf certificate supports OCSP
            try {
                ocspResponderUrl = new URL(mainCertExtractor.getOcspServerUrl());
                supportsOcsp = true;
            } catch (NoSuchFieldException ex) {
                LOGGER.error("Cannot extract OCSP responder URL from leaf certificate. This certificate likely does not support OCSP.");
                supportsOcsp = false;
                return;
            } catch (Exception ex) {
                LOGGER.error("Failed to extract OCSP responder URL from leaf certificate. Cannot make an OCSP request.");
                return;
            }

            OCSPRequest ocspRequest = new OCSPRequest(serverCertificateChain, ocspResponderUrl);

            // First Request Message with first fixed nonce test value
            OCSPRequestMessage ocspFirstRequestMessage = ocspRequest.createDefaultRequestMessage();
            ocspFirstRequestMessage.setNonce(new BigInteger(String.valueOf(NONCE_TEST_VALUE_1)));
            ocspFirstRequestMessage.addExtension(OCSPResponseTypes.NONCE.getOID());
            firstResponse = ocspRequest.makeRequest(ocspFirstRequestMessage);

            // If nonce is supported used, check if server actually replies
            // with a different one immediately after
            if (firstResponse.getNonce() != null) {
                supportsNonce = true;
                OCSPRequestMessage ocspSecondRequestMessage = ocspRequest.createDefaultRequestMessage();
                ocspSecondRequestMessage.setNonce(new BigInteger(String.valueOf(NONCE_TEST_VALUE_2)));
                ocspSecondRequestMessage.addExtension(OCSPResponseTypes.NONCE.getOID());
                secondResponse = ocspRequest.makeRequest(ocspSecondRequestMessage);
                LOGGER.debug(secondResponse.toString());
            } else {
                supportsNonce = false;
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
        tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
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
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new OcspResult(null, false, false, false, null, null, null);
    }
}
