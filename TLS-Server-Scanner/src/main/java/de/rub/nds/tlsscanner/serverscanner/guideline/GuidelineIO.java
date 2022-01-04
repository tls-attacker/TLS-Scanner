/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateAgilityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateCurveGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateSignatureCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateValidityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateVersionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtendedKeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmStrengthCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeySizeCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsGuidelineCheck;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class GuidelineIO {

    private static final Logger LOGGER = LogManager.getLogger(GuidelineIO.class.getName());
    public static final List<String> GUIDELINES = Arrays.asList("bsi.xml", "nist.xml");

    private static final List<Class<? extends GuidelineCheck>> CHECKS =
        Arrays.asList(AnalyzedPropertyGuidelineCheck.class, CertificateAgilityGuidelineCheck.class,
            CertificateCurveGuidelineCheck.class, CertificateValidityGuidelineCheck.class,
            CertificateVersionGuidelineCheck.class, CipherSuiteGuidelineCheck.class,
            ExtendedKeyUsageCertificateCheck.class, ExtensionGuidelineCheck.class, HashAlgorithmsGuidelineCheck.class,
            HashAlgorithmStrengthCheck.class, KeySizeCertGuidelineCheck.class, KeyUsageCertificateCheck.class,
            NamedGroupsGuidelineCheck.class, SignatureAlgorithmsCertificateGuidelineCheck.class,
            SignatureAlgorithmsGuidelineCheck.class, SignatureAndHashAlgorithmsGuidelineCheck.class,
            SignatureAndHashAlgorithmsCertificateGuidelineCheck.class, CertificateSignatureCheck.class);

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

    public static void writeGuideline(Guideline guideline, Path path) throws JAXBException {
        List<Class<?>> classes = new ArrayList<>(CHECKS);
        classes.add(Guideline.class);
        JAXBContext jc = JAXBContext.newInstance(classes.toArray(new Class[0]));
        Marshaller marshaller = jc.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(guideline, path.toFile());
    }

    private static Guideline readGuidelineUnchecked(String resource) {
        try {
            return readGuideline(resource);
        } catch (IOException | XMLStreamException | JAXBException exc) {
            LOGGER.warn("Failed reading Guideline.", exc);
        }
        return null;
    }

    public static List<Guideline> readGuidelines(List<String> guidelines) {
        return guidelines.stream().map(GuidelineIO::readGuidelineUnchecked).filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
}
