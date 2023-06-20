/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.guideline;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.report.ScanReport;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.util.JAXBSource;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
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

public final class GuidelineIO<R extends ScanReport<R>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final Map<Integer, JAXBContext> contextMap = new HashMap<>();

    private final JAXBContext context;

    public GuidelineIO(
            Class<? extends AnalyzedProperty> analyzedPropertyClass,
            Set<Class<? extends GuidelineCheck<R>>> supportedGuidelineCheckClasses)
            throws JAXBException {
        this.context = getJAXBContext(analyzedPropertyClass, supportedGuidelineCheckClasses);
    }

    private JAXBContext getJAXBContext(
            Class<? extends AnalyzedProperty> analyzedPropertyClass,
            Set<Class<? extends GuidelineCheck<R>>> supportedGuidelineCheckClasses)
            throws JAXBException {
        // Check contextMap for matching context before trying to load another one
        int classesHash = Objects.hash(analyzedPropertyClass, supportedGuidelineCheckClasses);
        if (contextMap.containsKey(classesHash)) {
            return contextMap.get(classesHash);
        }

        Class<?>[] contextClasses = new Class<?>[2 + supportedGuidelineCheckClasses.size()];
        contextClasses[0] = Guideline.class;
        contextClasses[1] = analyzedPropertyClass;
        int index = 2;
        for (Class<? extends GuidelineCheck<R>> guidelineCheckClass :
                supportedGuidelineCheckClasses) {
            contextClasses[index] = guidelineCheckClass;
            index++;
        }

        JAXBContext context = JAXBContext.newInstance(contextClasses);
        contextMap.put(classesHash, context);
        return context;
    }

    public void write(File f, Guideline<R> guideline) throws IOException, JAXBException {
        write(new FileOutputStream(f), guideline);
    }

    public void write(OutputStream outputStream, Guideline<R> guideline)
            throws JAXBException, IOException {
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        try (ByteArrayOutputStream tempStream = new ByteArrayOutputStream()) {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(new JAXBSource(context, guideline), new StreamResult(tempStream));

            String xml_text = tempStream.toString();
            // and we modify all line separators to the system dependant line separator
            xml_text = xml_text.replaceAll("\r?\n", System.lineSeparator());
            outputStream.write(xml_text.getBytes());
        } catch (TransformerException e) {
            LOGGER.warn(e);
        }
        outputStream.close();
    }

    public Guideline<R> read(File f) throws IOException, JAXBException, XMLStreamException {
        return read(new FileInputStream(f));
    }

    public Guideline<R> read(InputStream inputStream)
            throws JAXBException, IOException, XMLStreamException {
        Unmarshaller unmarshaller = context.createUnmarshaller();
        unmarshaller.setEventHandler(
                event -> {
                    // raise an Exception also on Warnings
                    return false;
                });
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        Guideline<R> guideline = (Guideline<R>) unmarshaller.unmarshal(xsr);
        inputStream.close();
        return guideline;
    }
}
