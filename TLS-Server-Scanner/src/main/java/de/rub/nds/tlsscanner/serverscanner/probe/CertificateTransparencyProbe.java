/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.asn1.model.*;
import de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateInformationExtractor;

import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponse;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestamp;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampList;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLog;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLogList;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLogListLoader;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampListParser;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.CertificateTransparencyResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import org.bouncycastle.crypto.tls.Certificate;

import java.time.Duration;
import java.util.*;

public class CertificateTransparencyProbe extends TlsProbe {

    private Certificate serverCertChain;
    private OCSPResponse stapledOcspResponse;

    private boolean supportsPrecertificateSCTs;
    private boolean supportsHandshakeSCTs;
    private boolean supportsOcspSCTs;
    private boolean meetsChromeCTPolicy = false;
    private SignedCertificateTimestampList precertificateSctList;
    private SignedCertificateTimestampList handshakeSctList;
    private SignedCertificateTimestampList ocspSctList;

    public CertificateTransparencyProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CERTIFICATE_TRANSPARENCY, config);
    }

    @Override
    public ProbeResult executeTest() {
        Config tlsConfig = initTlsConfig();

        if (serverCertChain == null) {
            LOGGER.warn("Couldn't fetch certificate chain from server!");
            return getCouldNotExecuteResult();
        }

        getPrecertificateSCTs();
        getTlsHandshakeSCTs(tlsConfig);
        evaluateChromeCtPolicy();

        return new CertificateTransparencyResult(supportsPrecertificateSCTs, supportsHandshakeSCTs, supportsOcspSCTs,
            meetsChromeCTPolicy, precertificateSctList, handshakeSctList, ocspSctList);
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

        tlsConfig.setAddSignedCertificateTimestampExtension(true);

        return tlsConfig;
    }

    private void getPrecertificateSCTs() {
        supportsPrecertificateSCTs = false;
        org.bouncycastle.asn1.x509.Certificate singleCert = serverCertChain.getCertificateAt(0);
        CertificateInformationExtractor certInformationExtractor = new CertificateInformationExtractor(singleCert);
        try {
            Asn1Sequence precertificateSctExtension = certInformationExtractor.getPrecertificateSCTs();
            if (precertificateSctExtension != null) {
                supportsPrecertificateSCTs = true;

                Asn1EncapsulatingOctetString outerContentEncapsulation =
                    (Asn1EncapsulatingOctetString) precertificateSctExtension.getChildren().get(1);

                byte[] encodedSctList = null;

                // Some CAs (e.g. DigiCert) embed the DER-encoded SCT in an Asn1EncapsulatingOctetString
                // instead of an Asn1PrimitiveOctetString
                Asn1Field innerContentEncapsulation = (Asn1Field) outerContentEncapsulation.getChildren().get(0);
                if (innerContentEncapsulation instanceof Asn1PrimitiveOctetString) {
                    Asn1PrimitiveOctetString innerPrimitiveOctetString =
                        (Asn1PrimitiveOctetString) innerContentEncapsulation;
                    encodedSctList = innerPrimitiveOctetString.getValue();
                } else if (innerContentEncapsulation instanceof Asn1EncapsulatingOctetString) {
                    Asn1EncapsulatingOctetString innerEncapsulatingOctetString =
                        (Asn1EncapsulatingOctetString) innerContentEncapsulation;
                    encodedSctList = innerEncapsulatingOctetString.getContent().getOriginalValue();
                }
                SignedCertificateTimestampListParser sctListParser =
                    new SignedCertificateTimestampListParser(0, encodedSctList, serverCertChain, true);
                precertificateSctList = sctListParser.parse();
            }
        } catch (Exception e) {
            LOGGER.warn("Couldn't determine Signed Certificate Timestamp Extension in certificate.", e);
        }
    }

    private void getTlsHandshakeSCTs(Config tlsConfig) {
        supportsHandshakeSCTs = false;

        State state = new State(tlsConfig);
        executeState(state);
        List<ExtensionType> supportedExtensions = new ArrayList<>(state.getTlsContext().getNegotiatedExtensionSet());

        try {
            if (supportedExtensions.contains(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP)) {
                if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
                    ServerHelloMessage serverHelloMessage = (ServerHelloMessage) WorkflowTraceUtil
                        .getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace());
                    if (serverHelloMessage != null
                        && serverHelloMessage.containsExtension(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP)) {

                        SignedCertificateTimestampExtensionMessage sctExtensionMessage =
                            serverHelloMessage.getExtension(SignedCertificateTimestampExtensionMessage.class);
                        byte[] encodedSctList = sctExtensionMessage.getSignedTimestamp().getOriginalValue();

                        SignedCertificateTimestampListParser sctListParser =
                            new SignedCertificateTimestampListParser(0, encodedSctList, serverCertChain, false);
                        handshakeSctList = sctListParser.parse();

                        supportsHandshakeSCTs = true;
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.warn(
                "Couldn't parse Signed Certificate Timestamp List from signed_certificate_timestamp extension data.");
        }
    }

    /**
     * Evaluates if Chrome's CT Policy is met. See https://github.com/chromium/ct-policy/blob/master/ct_policy.md for
     * detailed information about Chrome's CT Policy.
     */
    private void evaluateChromeCtPolicy() {

        if (!supportsPrecertificateSCTs) {
            List<SignedCertificateTimestamp> combinedSctList = new ArrayList<>();
            if (supportsHandshakeSCTs) {
                combinedSctList.addAll(handshakeSctList.getCertificateTimestampList());
            }
            if (supportsOcspSCTs) {
                combinedSctList.addAll(ocspSctList.getCertificateTimestampList());
            }

            meetsChromeCTPolicy = hasGoogleAndNonGoogleScts(combinedSctList);
        } else {
            Date endDate = serverCertChain.getCertificateAt(0).getEndDate().getDate();
            Date startDate = serverCertChain.getCertificateAt(0).getStartDate().getDate();
            Duration validityDuration = Duration.between(startDate.toInstant(), endDate.toInstant());

            boolean hasEnoughPrecertificateSCTs = false;
            if (validityDuration.minusDays(30 * 15).isNegative()) {
                // Certificate is valid for 15 months or less, two embedded precertificate SCTs are required
                hasEnoughPrecertificateSCTs = precertificateSctList.getCertificateTimestampList().size() >= 2;
            } else if (validityDuration.minusDays(30 * 27).isNegative()) {
                // Certificate is valid for 15 to 27 months, three embedded precertificate SCTs are required
                hasEnoughPrecertificateSCTs = precertificateSctList.getCertificateTimestampList().size() >= 3;
            } else if (validityDuration.minusDays(30 * 39).isNegative()) {
                // Certificate is valid for 27 to 39 months, four embedded precertificate SCTs are required
                hasEnoughPrecertificateSCTs = precertificateSctList.getCertificateTimestampList().size() >= 4;
            } else {
                // Certificate is valid for more than 39 months, five embedded precertificate SCTs are required
                hasEnoughPrecertificateSCTs = precertificateSctList.getCertificateTimestampList().size() >= 5;
            }

            boolean hasGoogleAndNonGoogleScts =
                hasGoogleAndNonGoogleScts(precertificateSctList.getCertificateTimestampList());
            meetsChromeCTPolicy = hasGoogleAndNonGoogleScts && hasEnoughPrecertificateSCTs;
        }
    }

    private boolean hasGoogleAndNonGoogleScts(List<SignedCertificateTimestamp> sctList) {
        CtLogList ctLogList = CtLogListLoader.loadLogList();

        boolean hasGoogleSct = false;
        boolean hasNonGoogleSct = false;

        for (SignedCertificateTimestamp sct : sctList) {
            CtLog ctLog = ctLogList.getCtLog(sct.getLogId());
            if (ctLog != null) {
                if ("Google".equals(ctLog.getOperator())) {
                    hasGoogleSct = true;
                } else {
                    hasNonGoogleSct = true;
                }
            }

        }

        return hasGoogleSct && hasNonGoogleSct;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getCertificateChainList() != null && report.isProbeAlreadyExecuted(ProbeType.OCSP);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CertificateTransparencyResult(false, false, false, false, null, null, null);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverCertChain = report.getCertificateChainList().get(0).getCertificate();
    }
}
