package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceNormalizer;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.util.SNIUtil;

public abstract class BaseDispatcher implements IDispatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    protected void patchCertificate(State state, DispatchInformation dispatchInformation) throws IOException {
        String hostname;
        ServerNameIndicationExtensionMessage sni = SNIUtil.getSNIFromExtensions(dispatchInformation.chlo.getExtensions());
        hostname = SNIUtil.getServerNameFromSNIExtension(sni);
        if (hostname == null) {
            hostname = state.getConfig().getDefaultServerConnection().getHostname();
        }

        Config config = state.getConfig();
        CertificateKeyPair kp = config.getDefaultExplicitCertificateKeyPair();
        ByteArrayInputStream stream = new ByteArrayInputStream(kp.getCertificateBytes());
        org.bouncycastle.asn1.x509.Certificate ca_cert = Certificate.parse(stream).getCertificateAt(0);
        CustomPrivateKey ca_sk = kp.getPrivateKey();

        // stolen from server hello preparator
        // used to determine which kind of cert we need
        CipherSuite selectedSuite = null;
        if (state.getConfig().isEnforceSettings()) {
            selectedSuite = config.getDefaultSelectedCipherSuite();
        } else {
            for (CipherSuite suite : config.getDefaultServerSupportedCiphersuites()) {
                if (state.getTlsContext().getClientSupportedCiphersuites().contains(suite)) {
                    selectedSuite = suite;
                    break;
                }
            }
            if (selectedSuite == null) {
                selectedSuite = config.getDefaultSelectedCipherSuite();
            }
        }
        String kpType = null;
        int keysize = 0;
        CertificateKeyType ckt = AlgorithmResolver.getKeyExchangeAlgorithm(selectedSuite).getRequiredCertPublicKeyType();
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
                kpType = "EC";
                keysize = 256;
                break;
            default:
                LOGGER.warn("Unknown Cert Key Type {}", ckt);
                kpType = "RSA";
                keysize = 2048;
                break;
        }

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(kpType);
            kpg.initialize(keysize);
        } catch (NoSuchAlgorithmException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        KeyPair ckp = kpg.generateKeyPair();

        X500Name issuer = ca_cert.getSubject();
        BigInteger serial = BigInteger.valueOf(0);
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
        X509v3CertificateBuilder cert_builder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore.getTime(), notAfter.getTime(), subject, ckp.getPublic());

        List<GeneralName> altNames = new ArrayList<>();
        altNames.add(new GeneralName(GeneralName.dNSName, hostname));
        GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence(altNames.toArray(new GeneralName[] {})));
        cert_builder = cert_builder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        try {
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(ca_sk);
            X509CertificateHolder cert = cert_builder.build(signer);
            Certificate cert_lst = new Certificate(new org.bouncycastle.asn1.x509.Certificate[] { cert.toASN1Structure(), ca_cert });
            CertificateKeyPair finalCert = new CertificateKeyPair(cert_lst, ckp.getPrivate(), ckp.getPublic());
            config.setDefaultExplicitCertificateKeyPair(finalCert);
            finalCert.adjustInConfig(config, ConnectionEndType.SERVER);
        } catch (OperatorCreationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    protected ClientAdapterResult executeState(State state, DispatchInformation dispatchInformation) {
        WorkflowTrace trace = state.getWorkflowTrace();
        try {
            patchCertificate(state, dispatchInformation);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        normalizer.normalize(trace, state.getConfig(), state.getRunningMode());
        trace.setDirty(false);

        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        if (state.getConfig().isWorkflowExecutorShouldClose() &&
                dispatchInformation.additionalInformation.containsKey(ControlledClientDispatcher.class)) {
            @SuppressWarnings("unchecked")
            Future<ClientAdapterResult> cFuture = dispatchInformation.getAdditionalInformation(ControlledClientDispatcher.class, Future.class);
            try {
                return cFuture.get();
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