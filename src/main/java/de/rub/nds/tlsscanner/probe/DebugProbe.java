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
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1tool.xmlparser.Asn1XmlContent;
import de.rub.nds.tlsattacker.attacks.cca.*;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.CcaResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.cca.CcaTestResult;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static de.rub.nds.x509attacker.X509Attacker.*;

public class DebugProbe extends TlsProbe {
    private List<VersionSuiteListPair> versionSuiteListPairsList;

    public DebugProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CCA, config, 5);
        versionSuiteListPairsList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {

        registerXmlClasses();
        registerTypes();
        registerContexts();
        registerContentUnpackers();

        try {
            GeneralSubtree generalSubtree = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "AAAAAAAA"), BigInteger.valueOf(0), BigInteger.valueOf(10));
//            GeneralSubtree generalSubtree = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "test"), 0);
            DERIA5String deria5String = new DERIA5String("AAAAAAAA");
            byte[] encodedIa5String = deria5String.getEncoded();
            GeneralName generalName = new GeneralName(GeneralName.dNSName, "AAAAAAAA");
            // Parse certificate
            byte[] encodedName = generalName.getEncoded();
            byte[] encodedSubtree = generalSubtree.getEncoded();
            Asn1Parser asn1Parser = new Asn1Parser(encodedSubtree, false);
            List<Asn1Encodable> asn1Encodables = asn1Parser.parse(ParseNativeTypesContext.NAME);
            Asn1XmlContent asn1XmlContent = new Asn1XmlContent();

            asn1XmlContent.setAsn1Encodables(asn1Encodables);
        } catch (Exception e) {

        }
        CcaDelegate ccaDelegate = (CcaDelegate) getScannerConfig().getDelegate(CcaDelegate.class);
//        CcaCertificateManager ccaCertificateManager = CcaCertificateManager.getReference();
//        ccaCertificateManager.init(ccaDelegate);
//        CcaFileManager ccaFileManager = CcaFileManager.getReference()


        /**
         * Add any protocol version (1.0-1.2) to the versions we iterate
         */
        List<ProtocolVersion> desiredVersions = new LinkedList<>();
//        desiredVersions.add(ProtocolVersion.TLS11);
//        desiredVersions.add(ProtocolVersion.TLS10);
        desiredVersions.add(ProtocolVersion.TLS12);



        List<CipherSuite> cipherSuites = new LinkedList<>();

//        cipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
//        cipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
//        cipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
//        cipherSuites.add(CipherSuite.TLS_RSA_WITH_DES_CBC_SHA);
//        cipherSuites.addAll(CipherSuite.getImplemented());
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        List<CcaTestResult> resultList = new LinkedList<>();
        Boolean bypassable = false;
//        for (CcaWorkflowType ccaWorkflowType : CcaWorkflowType.values()) {
        CcaWorkflowType ccaWorkflowType = CcaWorkflowType.CRT_CKE_VRFY_CCS_FIN;
        CcaCertificateType ccaCertificateType = CcaCertificateType.ROOTv3_CAv3_LEAF_RSAv3_AdditionalCertAfterLeaf


                ;
//            for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
        for (ProtocolVersion protocolVersion : desiredVersions) {
            // Dummy for output since I do not iterate Ciphersuites
            CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
            CertificateMessage certificateMessage = null;
            Config tlsConfig = generateConfig();
            tlsConfig.setDefaultClientSupportedCiphersuites(cipherSuites);
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            // Needed for CyaSSL/WolfSSL. The server answers only to client hellos which have Version 1.0 in the Record Protocol
//          tlsConfig.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS10);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
            WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaDelegate, ccaWorkflowType,
                    ccaCertificateType);
            ApplicationMessage applicationMessage = new ApplicationMessage();
            trace.addTlsAction(new SendAction(applicationMessage));
            State state = new State(tlsConfig, trace);

            try {
                executeState(state);
            } catch (Exception E) {
                LOGGER.error("Error while testing for client authentication bypasses." + E);
            }
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
                bypassable = true;
                resultList.add(new CcaTestResult(true, ccaWorkflowType, ccaCertificateType,
                        protocolVersion, cipherSuite));
            } else {
                resultList.add(new CcaTestResult(false, ccaWorkflowType, ccaCertificateType,
                        protocolVersion, cipherSuite));
            }
        }
        return new CcaResult(bypassable ? TestResult.TRUE : TestResult.FALSE, resultList);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
       return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {}

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CcaResult(TestResult.COULD_NOT_TEST, null);
    }
    private Config generateConfig() {
        Config config = getScannerConfig().createConfig();
        config.setAutoSelectCertificate(false);
        config.setAddServerNameIndicationExtension(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

        List<NamedGroup> namedGroups = Arrays.asList(NamedGroup.values());
        config.setDefaultClientNamedGroups(namedGroups);

        return config;
    }
}