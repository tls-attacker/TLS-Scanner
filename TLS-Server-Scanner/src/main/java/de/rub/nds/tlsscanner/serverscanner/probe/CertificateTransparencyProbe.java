/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateInformationExtractor;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestamp;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampList;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampListParser;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLog;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLogList;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLogListLoader;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

import org.bouncycastle.crypto.tls.Certificate;

import java.io.ByteArrayInputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertificateTransparencyProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private Certificate serverCertChain;

    private TestResult supportsPrecertificateSCTs = TestResults.COULD_NOT_TEST;
    private TestResult supportsHandshakeSCTs = TestResults.COULD_NOT_TEST;
    private TestResult supportsOcspSCTs = TestResults.COULD_NOT_TEST;
    private TestResult meetsChromeCTPolicy = TestResults.COULD_NOT_TEST;

    private final SignedCertificateTimestampList precertificateSctList =
            new SignedCertificateTimestampList();
    private final SignedCertificateTimestampList handshakeSctList =
            new SignedCertificateTimestampList();
    ;
    private final SignedCertificateTimestampList ocspSctList = new SignedCertificateTimestampList();
    ;

    public CertificateTransparencyProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CERTIFICATE_TRANSPARENCY, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE,
                TlsAnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE,
                TlsAnalyzedProperty.SUPPORTS_SCTS_OCSP,
                TlsAnalyzedProperty.SUPPORTS_CHROME_CT_POLICY);
    }

    @Override
    public void executeTest() {
        supportsPrecertificateSCTs = getPrecertificateSCTs();
        supportsHandshakeSCTs = getTlsHandshakeSCTs();
        meetsChromeCTPolicy = evaluateChromeCtPolicy();
    }

    private TestResult getPrecertificateSCTs() {
        boolean supportsPrecertificateSCTs = false;
        org.bouncycastle.asn1.x509.Certificate singleCert = serverCertChain.getCertificateAt(0);
        CertificateInformationExtractor certInformationExtractor =
                new CertificateInformationExtractor(singleCert);

        Asn1Sequence precertificateSctExtension = certInformationExtractor.getPrecertificateSCTs();
        if (precertificateSctExtension != null) {
            supportsPrecertificateSCTs = true;

            Asn1EncapsulatingOctetString outerContentEncapsulation =
                    (Asn1EncapsulatingOctetString) precertificateSctExtension.getChildren().get(1);

            byte[] encodedSctList = null;

            // Some CAs (e.g. DigiCert) embed the DER-encoded SCT in an
            // Asn1EncapsulatingOctetString
            // instead of an Asn1PrimitiveOctetString
            Asn1Field innerContentEncapsulation =
                    (Asn1Field) outerContentEncapsulation.getChildren().get(0);
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
                    new SignedCertificateTimestampListParser(
                            new ByteArrayInputStream(encodedSctList), serverCertChain, true);
            sctListParser.parse(precertificateSctList);
        }
        if (supportsPrecertificateSCTs) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    private TestResult getTlsHandshakeSCTs() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddSignedCertificateTimestampExtension(true);
        State state = new State(tlsConfig);
        executeState(state);

        SignedCertificateTimestampExtensionMessage sctExtensionMessage =
                getNegotiatedExtension(
                        state.getWorkflowTrace(), SignedCertificateTimestampExtensionMessage.class);
        if (sctExtensionMessage != null) {
            byte[] encodedSctList = sctExtensionMessage.getSignedTimestamp().getOriginalValue();

            SignedCertificateTimestampListParser sctListParser =
                    new SignedCertificateTimestampListParser(
                            new ByteArrayInputStream(encodedSctList), serverCertChain, false);
            sctListParser.parse(handshakeSctList);
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    /**
     * Evaluates if Chrome's CT Policy is met. See
     * https://github.com/chromium/ct-policy/blob/master/ct_policy.md for detailed information about
     * Chrome's CT Policy.
     */
    private TestResult evaluateChromeCtPolicy() {
        boolean meetsChromeCTPolicy = false;
        if (supportsPrecertificateSCTs == TestResults.FALSE) {
            List<SignedCertificateTimestamp> combinedSctList = new ArrayList<>();
            if (supportsHandshakeSCTs == TestResults.TRUE) {
                combinedSctList.addAll(handshakeSctList.getCertificateTimestampList());
            }
            if (supportsOcspSCTs == TestResults.UNSUPPORTED) {
                /* TODO supportsOcspSCTs is never set or initialized! */
                combinedSctList.addAll(ocspSctList.getCertificateTimestampList());
            }
            meetsChromeCTPolicy = hasGoogleAndNonGoogleScts(combinedSctList);
        } else if (precertificateSctList != null) {
            Date endDate = serverCertChain.getCertificateAt(0).getEndDate().getDate();
            Date startDate = serverCertChain.getCertificateAt(0).getStartDate().getDate();
            Duration validityDuration =
                    Duration.between(startDate.toInstant(), endDate.toInstant());

            boolean hasEnoughPrecertificateSCTs = false;
            if (validityDuration.minusDays(30 * 15).isNegative()) {
                // Certificate is valid for 15 months or less, two embedded precertificate SCTs are
                // required
                hasEnoughPrecertificateSCTs =
                        precertificateSctList.getCertificateTimestampList().size() >= 2;
            } else if (validityDuration.minusDays(30 * 27).isNegative()) {
                // Certificate is valid for 15 to 27 months, three embedded precertificate SCTs are
                // required
                hasEnoughPrecertificateSCTs =
                        precertificateSctList.getCertificateTimestampList().size() >= 3;
            } else if (validityDuration.minusDays(30 * 39).isNegative()) {
                // Certificate is valid for 27 to 39 months, four embedded precertificate SCTs are
                // required
                hasEnoughPrecertificateSCTs =
                        precertificateSctList.getCertificateTimestampList().size() >= 4;
            } else {
                // Certificate is valid for more than 39 months, five embedded precertificate SCTs
                // are required
                hasEnoughPrecertificateSCTs =
                        precertificateSctList.getCertificateTimestampList().size() >= 5;
            }

            boolean hasGoogleAndNonGoogleScts =
                    hasGoogleAndNonGoogleScts(precertificateSctList.getCertificateTimestampList());
            meetsChromeCTPolicy = hasGoogleAndNonGoogleScts && hasEnoughPrecertificateSCTs;
        }

        if (meetsChromeCTPolicy) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
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
    protected Requirement getRequirements() {
        return new ProbeRequirement(TlsProbeType.OCSP, TlsProbeType.CERTIFICATE);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        serverCertChain = report.getCertificateChainList().get(0).getCertificate();
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setPrecertificateSctList(precertificateSctList);
        report.setHandshakeSctList(handshakeSctList);
        report.setOcspSctList(ocspSctList);

        put(TlsAnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE, supportsPrecertificateSCTs);
        put(TlsAnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE, supportsHandshakeSCTs);
        put(TlsAnalyzedProperty.SUPPORTS_SCTS_OCSP, supportsOcspSCTs);
        put(TlsAnalyzedProperty.SUPPORTS_CHROME_CT_POLICY, meetsChromeCTPolicy);
    }
}
