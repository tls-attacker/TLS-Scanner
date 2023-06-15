/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
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
import de.rub.nds.tlsscanner.serverscanner.io.TlsAnalyzedPropertyFactory;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.ValidationEvent;
import jakarta.xml.bind.ValidationEventHandler;
import jakarta.xml.bind.util.JAXBSource;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GuidelineIO {

    private static final Logger LOGGER = LogManager.getLogger();

    /** context initialization is expensive, we need to do that only once */
    private static JAXBContext context;

    static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {
            context =
                    JAXBContext.newInstance(
                            TlsAnalyzedProperty.class,
                            Guideline.class,
                            AnalyzedPropertyGuidelineCheck.class,
                            CertificateAgilityGuidelineCheck.class,
                            CertificateCurveGuidelineCheck.class,
                            CertificateValidityGuidelineCheck.class,
                            CertificateVersionGuidelineCheck.class,
                            CipherSuiteGuidelineCheck.class,
                            ExtendedKeyUsageCertificateCheck.class,
                            ExtensionGuidelineCheck.class,
                            HashAlgorithmsGuidelineCheck.class,
                            HashAlgorithmStrengthCheck.class,
                            KeySizeCertGuidelineCheck.class,
                            KeyUsageCertificateCheck.class,
                            NamedGroupsGuidelineCheck.class,
                            SignatureAlgorithmsCertificateGuidelineCheck.class,
                            SignatureAlgorithmsGuidelineCheck.class,
                            SignatureAndHashAlgorithmsGuidelineCheck.class,
                            SignatureAndHashAlgorithmsCertificateGuidelineCheck.class,
                            CertificateSignatureCheck.class,
                            TlsAnalyzedPropertyFactory.class);
        }
        return context;
    }

    public static void write(OutputStream outputStream, Guideline guideline)
            throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        try (ByteArrayOutputStream tempStream = new ByteArrayOutputStream()) {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(new JAXBSource(context, guideline), new StreamResult(tempStream));

            String xml_text = new String(tempStream.toByteArray());
            // and we modify all line separators to the system dependant line separator
            xml_text = xml_text.replaceAll("\r?\n", System.lineSeparator());
            outputStream.write(xml_text.getBytes());
        } catch (TransformerException E) {
            LOGGER.debug(E.getStackTrace());
        }
        outputStream.close();
    }

    public static void write(File f, Guideline guidline) throws IOException, JAXBException {
        write(new FileOutputStream(f), guidline);
    }

    public static Guideline read(InputStream inputStream)
            throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller unmarshaller = context.createUnmarshaller();
        unmarshaller.setEventHandler(
                new ValidationEventHandler() {
                    @Override
                    public boolean handleEvent(ValidationEvent event) {
                        // raise an Exception also on Warnings
                        return false;
                    }
                });
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        Guideline guideline = (Guideline) unmarshaller.unmarshal(xsr);
        inputStream.close();
        return guideline;
    }

    public static Guideline read(File f) throws IOException, JAXBException, XMLStreamException {
        return read(new FileInputStream(f));
    }
}
