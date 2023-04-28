/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencers;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.io.TlsAnalyzedPropertyFactory;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.ValidationEvent;
import jakarta.xml.bind.ValidationEventHandler;
import jakarta.xml.bind.util.JAXBSource;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

public class RatingInfluencersIO {

    private static final Logger LOGGER = LogManager.getLogger();

    /** context initialization is expensive, we need to do that only once */
    private static JAXBContext context;

    static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (context == null) {
            context =
                    JAXBContext.newInstance(
                            RatingInfluencers.class,
                            TlsAnalyzedProperty.class,
                            RatingInfluencer.class,
                            PropertyResultRatingInfluencer.class,
                            TlsAnalyzedPropertyFactory.class);
        }
        return context;
    }

    public static void write(OutputStream outputStream, RatingInfluencers ratingInfluencers)
            throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        try (ByteArrayOutputStream tempStream = new ByteArrayOutputStream()) {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(
                    new JAXBSource(context, ratingInfluencers), new StreamResult(tempStream));

            String xml_text = new String(tempStream.toByteArray());
            // and we modify all line separators to the system dependant line separator
            xml_text = xml_text.replaceAll("\r?\n", System.lineSeparator());
            outputStream.write(xml_text.getBytes());
        } catch (TransformerException E) {
            LOGGER.debug(E.getStackTrace());
        }
        outputStream.close();
    }

    public static void write(File f, RatingInfluencers r) throws IOException, JAXBException {
        write(new FileOutputStream(f), r);
    }

    public static RatingInfluencers read(InputStream inputStream)
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
        RatingInfluencers ratingInfluencers = (RatingInfluencers) unmarshaller.unmarshal(xsr);
        inputStream.close();
        return ratingInfluencers;
    }

    public static RatingInfluencers read(File f)
            throws IOException, JAXBException, XMLStreamException {
        return read(new FileInputStream(f));
    }
}
