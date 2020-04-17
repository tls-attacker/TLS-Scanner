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
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveIa5String;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.ContextRegister;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.OcspResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import org.bouncycastle.crypto.tls.Certificate;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Nils Hanke - nils.hanke@rub.de
 */
public class OcspProbe extends TlsProbe {

    public OcspProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.OCSP, config, 0);
    }

    @Override
    public ProbeResult executeTest() {
        Config tlsConfig = initTlsConfig();
        Certificate serverCerts = CertificateFetcher.fetchServerCertificate(tlsConfig);
        String ocspUrl = extractOcspUrl(serverCerts);

        System.out.println(ocspUrl);
        return new OcspResult();
    }

    private Config initTlsConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);

        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        List<NamedGroup> namedGroups = Arrays.asList(NamedGroup.values());
        tlsConfig.setDefaultClientNamedGroups(namedGroups);
        List<SignatureAndHashAlgorithm> sigHashAlgos = Arrays.asList(SignatureAndHashAlgorithm.values());
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(sigHashAlgos);
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setDefaultClientSupportedCiphersuites(toTestList);
        tlsConfig.setStopActionsAfterFatal(true);
        return tlsConfig;
    }

    private static void registerContexts() {
        ContextRegister contextRegister = ContextRegister.getInstance();
        contextRegister.registerContext(ParseNativeTypesContext.NAME, ParseNativeTypesContext.class);
        contextRegister.registerContext(ParseOcspTypesContext.NAME, ParseOcspTypesContext.class);
    }

    private static void registerContentUnpackers() {
        ContentUnpackerRegister contentUnpackerRegister = ContentUnpackerRegister.getInstance();
        contentUnpackerRegister.registerContentUnpacker(new DefaultContentUnpacker());
        contentUnpackerRegister.registerContentUnpacker(new PrimitiveBitStringUnpacker());
    }

    // TODO: Needs cleanup and a sanity check! This is kind of a messy way to go
    // through the ASN.1 structure, but it works surprisingly well... If you're
    // trying to understand the way this works, open up an ASN.1 decoder next to
    // the code and go through it hierarchically.
    private String extractOcspUrl(Certificate cert) {
        String ocspUrlResult = null;
        org.bouncycastle.asn1.x509.Certificate mainServerCert = cert.getCertificateAt(0);
        try {
            byte[] mainServerCertAsn1 = mainServerCert.getEncoded();

            // Init ASN.1 Tool
            registerContexts();
            registerContentUnpackers();

            // Parse ASN.1 structure of the certificate
            Asn1Parser asn1Parser = new Asn1Parser(mainServerCertAsn1, false);
            List<Asn1Encodable> asn1Encodables = asn1Parser.parse(ParseOcspTypesContext.NAME);

            // Navigate through the mess to the OCSP URL. First, just unroll the
            // two outer ASN.1 sequences to get to most of the information
            // stored in a X.509 certificate.
            Asn1Sequence innerObjects = (Asn1Sequence) ((Asn1Sequence) asn1Encodables.get(0)).getChildren().get(0);

            // Get sequence containing X.509 extensions
            Asn1Sequence x509Extensions = null;

            for (Asn1Encodable enc : innerObjects.getChildren()) {
                if (enc instanceof Asn1Sequence) {
                    if (((Asn1Sequence) enc).getIdentifierOctets().getOriginalValue().length > 0) {
                        // -93 == 0xA3 signed. It's the explicit tag for X.509
                        // extension in the DER encoded form, therefore a good
                        // value to search for.
                        if (((Asn1Sequence) enc).getIdentifierOctets().getOriginalValue()[0] == -93) {
                            x509Extensions = (Asn1Sequence) enc;
                            break;
                        }
                    }
                }
            }

            // Now that we found the extensions, search for the
            // 'authorityInfoAccess' extension
            List<Asn1Encodable> x509ExtensionsSequences = ((Asn1Sequence) x509Extensions.getChildren().get(0))
                    .getChildren();
            Asn1Sequence authorityInfoAccess = null;
            for (Asn1Encodable enc : x509ExtensionsSequences) {
                if (enc instanceof Asn1Sequence) {
                    Asn1ObjectIdentifier objectIdentifier = (Asn1ObjectIdentifier) (((Asn1Sequence) enc).getChildren()
                            .get(0));
                    if (objectIdentifier.getValue().equals("1.3.6.1.5.5.7.1.1")) {
                        authorityInfoAccess = (Asn1Sequence) enc;
                        break;
                    }
                }
            }

            // get(0) is the Object Identifier we checked, get(1) the Octet
            // String with the content
            // The Octet String has a sequence as child, and one of them has
            // the desired OCSP information.
            // Almost there!
            Asn1EncapsulatingOctetString authorityInfoAccessEntities = (Asn1EncapsulatingOctetString) authorityInfoAccess
                    .getChildren().get(1);
            Asn1Sequence authorityInfoAccessEntitiesSequence = (Asn1Sequence) authorityInfoAccessEntities.getChildren()
                    .get(0);

            List<Asn1Encodable> ocspInformation = null;

            // Now let's check if we have OCSP information embedded...
            for (Asn1Encodable enc : authorityInfoAccessEntitiesSequence.getChildren()) {
                if (enc instanceof Asn1Sequence) {
                    Asn1ObjectIdentifier objectIdentifier = (Asn1ObjectIdentifier) ((Asn1Sequence) enc).getChildren()
                            .get(0);
                    if (objectIdentifier.getValue().equals("1.3.6.1.5.5.7.48.1")) {
                        ocspInformation = ((Asn1Sequence) enc).getChildren();
                        break;
                    }
                }
            }

            // If we found the OCSP information, let's extract it and we're
            // done!
            if (ocspInformation != null) {
                Asn1PrimitiveIa5String ocspUrlIa5String = null;
                if (ocspInformation.size() > 1 && ocspInformation.get(1) instanceof Asn1PrimitiveIa5String) {
                    ocspUrlIa5String = (Asn1PrimitiveIa5String) ocspInformation.get(1);
                }
                ocspUrlResult = ocspUrlIa5String.getValue();
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            e.printStackTrace();
            LOGGER.error("Could not determine OCSP URL from given certificate");
        } catch (ParserException e) {
            e.printStackTrace();
            LOGGER.error("An error occurred during the parsing of the certificate's ASN.1 structure.");
        }
        return ocspUrlResult;
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
        return new OcspResult();
    }
}
