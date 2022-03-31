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
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.OcspResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ocsp.OcspCertificateResult;
import de.rub.nds.tlsscanner.serverscanner.requirements.ProbeRequirement;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.bouncycastle.crypto.tls.Certificate;

public class OcspProbe extends TlsProbe {

    private List<CertificateChain> serverCertChains;
    private List<NamedGroup> tls13NamedGroups;

    private List<OcspCertificateResult> certResults;
    private List<CertificateStatusRequestExtensionMessage> tls13CertStatus;

    public static final int NONCE_TEST_VALUE_1 = 42;
    public static final int NONCE_TEST_VALUE_2 = 1337;
    private static final long STAPLED_NONCE_RANDOM_SEED = 42;
    private static final int STAPLED_NONCE_RANDOM_BIT_LENGTH = 128;

    public OcspProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.OCSP, config);
        super.properties.add(AnalyzedProperty.SUPPORTS_OCSP);
        super.properties.add(AnalyzedProperty.SUPPORTS_OCSP_STAPLING);
        super.properties.add(AnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE);
        super.properties.add(AnalyzedProperty.SUPPORTS_STAPLED_NONCE);
        super.properties.add(AnalyzedProperty.MUST_STAPLE);
        super.properties.add(AnalyzedProperty.SUPPORTS_NONCE);
        super.properties.add(AnalyzedProperty.STAPLED_RESPONSE_EXPIRED);
        super.properties.add(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13);
        super.properties.add(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = initTlsConfig();
        if (serverCertChains == null) {
            LOGGER.warn("Couldn't fetch certificate chains from server!");
            return;
        }
        this.certResults = new LinkedList<>();
        for (CertificateChain serverCertChain : this.serverCertChains) {
            OcspCertificateResult certResult = new OcspCertificateResult(serverCertChain);

            getMustStaple(serverCertChain.getCertificate(), certResult);
            getStapledResponse(tlsConfig, certResult);
            performRequest(serverCertChain.getCertificate(), certResult);

            this.certResults.add(certResult);
        }
        if (!this.tls13NamedGroups.isEmpty()) 
            this.tls13CertStatus = getCertificateStatusFromCertificateEntryExtension();
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

    private Config initTlsConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);

        tlsConfig.setCertificateStatusRequestExtensionRequestExtension(prepareNonceExtension());
        tlsConfig.setAddCertificateStatusRequestExtension(true);

        return tlsConfig;
    }

    @Override
    protected ProbeRequirement getRequirements(SiteReport report) {
        return new ProbeRequirement(report).requireProbeTypes(ProbeType.NAMED_GROUPS, ProbeType.CERTIFICATE);
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

	@Override
	protected void mergeData(SiteReport report) {
		report.setOcspResults(this.certResults);

        super.setPropertyReportValue(AnalyzedProperty.SUPPORTS_OCSP, getConclusiveSupportsOcsp());
        super.setPropertyReportValue(AnalyzedProperty.SUPPORTS_OCSP_STAPLING, getConclusiveSupportsStapling());
        super.setPropertyReportValue(AnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE, getConclusiveIncludesCertMessage());
        super.setPropertyReportValue(AnalyzedProperty.SUPPORTS_STAPLED_NONCE, getConclusiveSupportsStapledNonce());
        super.setPropertyReportValue(AnalyzedProperty.MUST_STAPLE, getConclusiveMustStaple());
        super.setPropertyReportValue(AnalyzedProperty.SUPPORTS_NONCE, getConclusiveSupportsNonce());
        super.setPropertyReportValue(AnalyzedProperty.STAPLED_RESPONSE_EXPIRED, getConclusiveStapledResponseExpired());

        if (this.tls13CertStatus != null) {
            if (this.tls13CertStatus.size() == 1) {
                super.setPropertyReportValue(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResults.TRUE);
                super.setPropertyReportValue(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResults.FALSE);
            } else if (tls13CertStatus.size() > 1) {
                super.setPropertyReportValue(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResults.TRUE);
                super.setPropertyReportValue(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResults.TRUE);
            } else {
                super.setPropertyReportValue(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResults.FALSE);
                super.setPropertyReportValue(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResults.FALSE);
            }
        } else {
            super.setPropertyReportValue(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResults.COULD_NOT_TEST);
            super.setPropertyReportValue(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResults.COULD_NOT_TEST);
        }		
	}
	

    private TestResult getConclusiveSupportsOcsp() {
        boolean foundFalse = false;
        if (this.certResults != null) {
            for (OcspCertificateResult result : this.certResults) {
                if (Boolean.TRUE.equals(result.getSupportsOcsp())) 
                    return TestResults.TRUE;
                else if (Boolean.FALSE.equals(result.getSupportsOcsp()))
                    foundFalse = true;                
            }
            if (foundFalse)
                return TestResults.FALSE;            
        }
        return TestResults.ERROR_DURING_TEST;
    }
    
	private TestResult getConclusiveSupportsStapling() {
        if (this.certResults != null) {
            for (OcspCertificateResult result : this.certResults) {
                if (result.isSupportsStapling()) 
                    return TestResults.TRUE;                
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveIncludesCertMessage() {
        if (this.certResults != null) {
            for (OcspCertificateResult result : this.certResults) {
                if (result.getStapledResponse() != null) 
                    return TestResults.TRUE;                
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveSupportsStapledNonce() {
        if (this.certResults != null) {
            for (OcspCertificateResult result : this.certResults) {
                if (result.getStapledResponse() != null && result.getStapledResponse().getNonce() != null) 
                    return TestResults.TRUE;                
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveMustStaple() {
        if (this.certResults != null) {
            for (OcspCertificateResult result : this.certResults) {
                if (result.isMustStaple()) 
                    return TestResults.TRUE;                
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveSupportsNonce() {
        if (this.certResults != null) {
            for (OcspCertificateResult result : this.certResults) {
                if (result.isSupportsNonce()) 
                    return TestResults.TRUE;                
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveStapledResponseExpired() {
        if (this.certResults != null) {
            for (OcspCertificateResult result : this.certResults) {
                if (result.isStapledResponseExpired()) 
                    return TestResults.TRUE;                
            }
        }
        return TestResults.FALSE;
    }
}
