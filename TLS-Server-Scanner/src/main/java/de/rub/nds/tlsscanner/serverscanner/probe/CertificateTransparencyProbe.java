/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 * <p>
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 * <p>
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateInformationExtractor;

import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponse;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestamp;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampList;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampListParser;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLog;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLogList;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class CertificateTransparencyProbe extends TlsProbe {

    private Certificate serverCertChain;
    private OCSPResponse stapledOcspResponse;

    private boolean supportsPrecertificateSCTs;
    private boolean supportsHandshakeSCTs;
    private boolean supportsOcspSCTs;
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
        getOcspResponseScts();

        return new CertificateTransparencyResult(supportsPrecertificateSCTs, supportsHandshakeSCTs,
                supportsOcspSCTs, precertificateSctList, handshakeSctList, ocspSctList);
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

                Asn1EncapsulatingOctetString outerContentEncapsulation = (Asn1EncapsulatingOctetString)
                        precertificateSctExtension.getChildren().get(1);
                Asn1PrimitiveOctetString innerContentEncapsulation = (Asn1PrimitiveOctetString)
                        outerContentEncapsulation.getChildren().get(0);
                byte[] encodedSctList = innerContentEncapsulation.getValue();

                precertificateSctList = SignedCertificateTimestampListParser.parseTimestampList(encodedSctList,
                        serverCertChain, true);
            }
        } catch (Exception e) {
            LOGGER.warn("Couldn't determine Signed Certificate Timestamp Extension in certificate.");
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
                    ServerHelloMessage serverHelloMessage = (ServerHelloMessage)
                            WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace());
                    if (serverHelloMessage != null
                            && serverHelloMessage.containsExtension(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP)) {

                        SignedCertificateTimestampExtensionMessage sctExtensionMessage
                                = serverHelloMessage.getExtension(SignedCertificateTimestampExtensionMessage.class);
                        byte[] signedCertificateTimestampList = sctExtensionMessage.getSignedTimestamp().getOriginalValue();
                        handshakeSctList = SignedCertificateTimestampListParser.parseTimestampList(signedCertificateTimestampList,
                                serverCertChain, false);

                        supportsHandshakeSCTs = true;
                    }
                }
            }
        } catch (ParserException e) {
            LOGGER.warn("Couldn't parse Signed Certificate Timestamp List from signed_certificate_timestamp extension data.");
        }
    }

    private void getOcspResponseScts() {
        supportsOcspSCTs = false;
        if (stapledOcspResponse != null) {
            // TODO: Implement this using stapledOcspResponse.
            //  The OCSPResponse class needs to modified to support OCSP extensions (primarily singleExtension)
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getCertificateChain() != null && report.isProbeAlreadyExecuted(ProbeType.OCSP);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return null;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverCertChain = report.getCertificateChain().getCertificate();
        stapledOcspResponse = report.getStapledOcspResponse();
    }
}
