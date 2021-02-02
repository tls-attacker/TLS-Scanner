/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceNormalizer;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher.ControlledClientDispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.util.IPUtil;
import de.rub.nds.tlsscanner.clientscanner.util.SNIUtil;
import de.rub.nds.tlsscanner.clientscanner.workflow.CertificatePatchAction;
import de.rub.nds.tlsscanner.clientscanner.workflow.CertificatePatchException;
import de.rub.nds.tlsscanner.clientscanner.workflow.CertificatePatcher;

public abstract class BaseExecutingDispatcher implements Dispatcher, CertificatePatcher {
    private static final Logger LOGGER = LogManager.getLogger();
    private static long serialCounter = 0;

    // #region Certificate stuff

    protected CertificateKeyType determineCertificateKeyType(State state) {
        // stolen from server hello preparator
        // used to determine which kind of cert we need
        final Config config = state.getConfig();
        CipherSuite selectedSuite = null;
        if (config.isEnforceSettings()) {
            selectedSuite = config.getDefaultSelectedCipherSuite();
        } else {
            if (state.getTlsContext().getClientSupportedCiphersuites() != null) {
                for (CipherSuite suite : config.getDefaultServerSupportedCiphersuites()) {
                    if (state.getTlsContext().getClientSupportedCiphersuites().contains(suite)) {
                        selectedSuite = suite;
                        break;
                    }
                }
            }
            if (selectedSuite == null) {
                LOGGER.warn("Could not find common Ciphersuite; falling back to default");
                selectedSuite = config.getDefaultSelectedCipherSuite();
            }
        }

        CertificateKeyType ckt;
        if (selectedSuite.isTLS13()) {
            // TODO look at clients prefered signature algorithms
            ckt = CertificateKeyType.ECDSA;
        } else {
            ckt = AlgorithmResolver.getCertificateKeyType(selectedSuite);
        }
        LOGGER.debug("Determined cert key type {} (assuming CipherSuite {})", ckt, selectedSuite);
        return ckt;
    }

    protected KeyPair generateCertificateKeyPair(CertificateKeyType ckt) {
        String kpType = null;
        int keysize = 0;
        switch (ckt) {
            case DH:
                kpType = "DiffieHellman";
                keysize = 1024;
                break;
            case RSA:
                kpType = "RSA";
                keysize = 2048;
                break;
            case DSS:
                kpType = "DSA";
                keysize = 1024;
                break;
            case ECDSA:
            case ECDH:
                kpType = "EC";
                keysize = 256;
                break;
            default:
                LOGGER.error("Unknown Cert Key Type {} - Falling back to RSA", ckt);
                kpType = "RSA";
                keysize = 2048;
                break;
        }

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(kpType);
            kpg.initialize(keysize);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Failed to create keyPair", e);
            throw new RuntimeException("Failed to create keyPair", e);
        }
        return kpg.genKeyPair();
    }

    protected X509v3CertificateBuilder generateLeafCertificate(String hostname,
            org.bouncycastle.asn1.x509.Certificate parent, PublicKey myPubKey) throws CertIOException {
        X500Name issuer = parent.getSubject();
        @SuppressWarnings("squid:S2696")
        BigInteger serial = BigInteger.valueOf(serialCounter++);
        Calendar notBefore = new GregorianCalendar();
        notBefore.add(Calendar.DAY_OF_MONTH, -1);
        Calendar notAfter = new GregorianCalendar();
        notAfter.add(Calendar.DAY_OF_MONTH, -1);
        notAfter.add(Calendar.YEAR, 1);
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "DE")
                .addRDN(BCStyle.ST, "NRW")
                .addRDN(BCStyle.L, "Bochum")
                .addRDN(BCStyle.O, "RUB")
                .addRDN(BCStyle.OU, "NDS")
                .addRDN(BCStyle.CN, hostname)
                .build();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore.getTime(),
                notAfter.getTime(), subject, myPubKey);

        // add SAN
        List<GeneralName> altNames = new ArrayList<>();
        int hnType = GeneralName.dNSName;
        if (IPUtil.validIP(hostname)) {
            hnType = GeneralName.iPAddress;
        }
        altNames.add(new GeneralName(hnType, hostname));
        GeneralNames subjectAltNames = GeneralNames
                .getInstance(new DERSequence(altNames.toArray(new GeneralName[] {})));
        certBuilder = certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

        return certBuilder;
    }

    protected Certificate generateCertificateChain(State state, String hostname, PublicKey pubKey)
            throws OperatorCreationException, IOException {
        CertificateKeyPair kp = state.getConfig().getDefaultExplicitCertificateKeyPair();
        ByteArrayInputStream stream = new ByteArrayInputStream(kp.getCertificateBytes());
        Certificate origCertChain = Certificate.parse(stream);
        // TODO allow more complex chains
        if (origCertChain.getLength() != 1) {
            throw new IllegalStateException(
                    "Can only handle original cert chains of length 1, got " + origCertChain.getLength());
        }
        org.bouncycastle.asn1.x509.Certificate parentCert = origCertChain.getCertificateAt(0);
        CustomPrivateKey parentSk = kp.getPrivateKey();

        X509v3CertificateBuilder certBuilder = generateLeafCertificate(hostname, parentCert, pubKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(parentSk);
        X509CertificateHolder cert = certBuilder.build(signer);
        return new Certificate(new org.bouncycastle.asn1.x509.Certificate[] { cert.toASN1Structure(), parentCert });
    }

    public void patchCertificate(State state) throws CertificatePatchException {
        String hostname;
        ServerNameIndicationExtensionMessage sni = SNIUtil.getSNIFromState(state);
        hostname = SNIUtil.getServerNameFromSNIExtension(sni);
        if (hostname == null) {
            hostname = state.getConfig().getDefaultServerConnection().getHostname();
        }
        if (hostname == null) {
            LOGGER.warn("No hostname given by client and none found in config, falling back to localhost");
            hostname = "localhost";
        }
        final Config config = state.getConfig();

        // generate keys
        CertificateKeyType ckt = determineCertificateKeyType(state);
        KeyPair ckp = generateCertificateKeyPair(ckt);

        Certificate cert_lst;
        try {
            cert_lst = generateCertificateChain(state, hostname, ckp.getPublic());
            CertificateKeyPair finalCert = new CertificateKeyPair(cert_lst, ckp.getPrivate(), ckp.getPublic());
            config.setDefaultExplicitCertificateKeyPair(finalCert);
            finalCert.adjustInConfig(config, ConnectionEndType.SERVER);
        } catch (OperatorCreationException | IOException e) {
            LOGGER.error("Failed to patch certificate", e);
            throw new CertificatePatchException(e);
        }
    }

    // #endregion

    // #region helper functions
    private void assertActionIsEqual(MessageAction aAction, MessageAction bAction) {
        List<ProtocolMessage> entryMsgs;
        List<ProtocolMessage> appendMsgs;
        if (aAction instanceof SendAction) {
            entryMsgs = ((SendAction) aAction).getMessages();
            appendMsgs = ((SendAction) bAction).getMessages();
        } else if (aAction instanceof ReceiveAction) {
            entryMsgs = ((ReceiveAction) aAction).getExpectedMessages();
            appendMsgs = ((ReceiveAction) bAction).getExpectedMessages();
        } else {
            throw new RuntimeException("[internal error] unknown MessageAction " + aAction);
        }
        if (entryMsgs.size() != appendMsgs.size()) {
            throw new RuntimeException(
                    "[internal error] entryTrace and actions we want to append diverge (different message count in action):"
                            + aAction + ", " + bAction);
        }
        for (int i = 0; i < entryMsgs.size(); i++) {
            ProtocolMessage aMsg = entryMsgs.get(i);
            ProtocolMessage bMsg = appendMsgs.get(i);
            if (!aMsg.getProtocolMessageType().equals(bMsg.getProtocolMessageType())) {
                throw new RuntimeException(
                        "[internal error] entryTrace and actions we want to append diverge (different message type)"
                                + aMsg + ", " + bMsg);
            }
        }
    }

    protected void extendWorkflowTraceValidatingPrefix(WorkflowTrace traceToExtend, WorkflowTrace prefixTrace,
            WorkflowTrace actionsToAppendWithPrefix) {
        final List<TlsAction> prefixActions;
        if (prefixTrace != null) {
            prefixActions = prefixTrace.getTlsActions();
        } else {
            prefixActions = new ArrayList<>();
        }
        final List<TlsAction> appendActions = actionsToAppendWithPrefix.getTlsActions();
        for (int i = 0; i < prefixActions.size(); i++) {
            TlsAction prefixAction = prefixActions.get(i);
            TlsAction appendAction = prefixActions.get(i);
            if (!prefixAction.getClass().equals(appendAction.getClass())) {
                throw new RuntimeException(
                        "[internal error] prefixTrace and actions we want to append diverge (different classes)");
            }

            if (prefixAction instanceof MessageAction) {
                assertActionIsEqual((MessageAction) prefixAction, (MessageAction) appendAction);
            }
        }
        traceToExtend.addTlsActions(appendActions.subList(prefixActions.size(), appendActions.size()));
    }

    private void extendWorkflowTrace(WorkflowTrace traceWithCHLO, WorkflowTraceType type, Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace entryTrace = factory.createTlsEntryWorkflowtrace(config.getDefaultServerConnection());
        entryTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        if (traceWithCHLO.getTlsActions().isEmpty()) {
            extendWorkflowTraceValidatingPrefix(traceWithCHLO, null, entryTrace);
        }
        WorkflowTrace actionsToAppend = factory.createWorkflowTrace(type, RunningModeType.SERVER);
        extendWorkflowTraceValidatingPrefix(traceWithCHLO, entryTrace, actionsToAppend);
    }

    protected void extendWorkflowTraceToApplication(WorkflowTrace traceWithCHLO, Config config, boolean dynamic) {
        // TODO distinguish different application layers, for now only http(s)
        extendWorkflowTrace(traceWithCHLO, dynamic ? WorkflowTraceType.DYNAMIC_HTTPS : WorkflowTraceType.HTTPS, config);
        config.setHttpsParsingEnabled(true);
    }

    // #endregion
    protected ClientAdapterResult executeState(State state, DispatchInformation dispatchInformation)
            throws DispatchException {
        return executeState(state, dispatchInformation, true);
    }

    protected ClientAdapterResult executeState(State state, DispatchInformation dispatchInformation,
            boolean patchCertificate)
            throws DispatchException {
        WorkflowTrace trace = state.getWorkflowTrace();
        if (patchCertificate) {
            CertificatePatchAction.insertInto(state.getWorkflowTrace(), this);
        }

        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        normalizer.normalize(trace, state.getConfig(), state.getRunningMode());
        trace.setDirty(false);

        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        state.getConfig().setWorkflowExecutorShouldOpen(false);
        if (state.getConfig().isWorkflowExecutorShouldClose() &&
                dispatchInformation.additionalInformation.containsKey(ControlledClientDispatcher.class)) {
            ControlledClientDispatchInformation ccInfo = dispatchInformation.getAdditionalInformation(
                    ControlledClientDispatcher.class, ControlledClientDispatchInformation.class);
            Future<ClientAdapterResult> cFuture = ccInfo.clientFuture;
            try {
                ClientAdapterResult res = cFuture.get();
                if (res == null) {
                    LOGGER.warn("Got null result from client");
                }
                return res;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted", e);
            } catch (ExecutionException e) {
                throw new RuntimeException("Error while getting client result", e);
            }
        }
        return null;
    }
}