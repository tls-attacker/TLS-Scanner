/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.ConsoleLogger;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateAgilityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateCurveGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateValidityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateVersionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtendedKeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HasPublicKeyCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmStrengthCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeySizeCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureCertificateCheck;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class GuidelineIO {

    public static final List<String> GUIDELINES = Arrays.asList("BSI-TR-02102-2.xml", "NIST.SP.800-52r2.xml");

    private static final List<Class<? extends GuidelineCheck>> CHECKS = Arrays.asList(
        AnalyzedPropertyGuidelineCheck.class, CertificateAgilityGuidelineCheck.class,
        CertificateCurveGuidelineCheck.class, CertificateValidityGuidelineCheck.class,
        CertificateVersionGuidelineCheck.class, CipherSuiteGuidelineCheck.class, ExtendedKeyUsageCertificateCheck.class,
        ExtensionGuidelineCheck.class, HashAlgorithmsGuidelineCheck.class, HashAlgorithmStrengthCheck.class,
        HasPublicKeyCertificateCheck.class, KeySizeCertGuidelineCheck.class, KeyUsageCertificateCheck.class,
        NamedGroupsGuidelineCheck.class, SignatureAlgorithmsCertGuidelineCheck.class,
        SignatureAlgorithmsGuidelineCheck.class, SignatureAndHashAlgorithmsGuidelineCheck.class,
        SignatureAndHashAlgorithmsCertGuidelineCheck.class, SignatureCertificateCheck.class);

    public static Guideline readGuideline(String resource) throws IOException, JAXBException, XMLStreamException {
        List<Class<?>> classes = new ArrayList<>(CHECKS);
        classes.add(Guideline.class);
        JAXBContext jc = JAXBContext.newInstance(classes.toArray(new Class[0]));
        Unmarshaller unmarshaller = jc.createUnmarshaller();
        try (InputStream is = GuidelineIO.class.getResourceAsStream("/guideline/" + resource)) {
            if (is == null) {
                throw new IOException("Resource not found. " + resource);
            }
            XMLStreamReader reader = XMLInputFactory.newInstance().createXMLStreamReader(is);
            JAXBElement<Guideline> element = unmarshaller.unmarshal(reader, Guideline.class);
            return element.getValue();
        }
    }

    private static Guideline readGuidelineUnchecked(String resource) {
        try {
            return readGuideline(resource);
        } catch (IOException | XMLStreamException | JAXBException exc) {
            ConsoleLogger.CONSOLE.warn("Failed reading Guideline.", exc);
        }
        return null;
    }

    public static List<Guideline> readGuidelines(List<String> guidelines) {
        return guidelines.stream().map(GuidelineIO::readGuidelineUnchecked).filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
}
