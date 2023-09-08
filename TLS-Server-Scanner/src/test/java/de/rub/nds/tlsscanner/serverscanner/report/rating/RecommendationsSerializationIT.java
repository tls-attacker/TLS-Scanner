/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.rating.PropertyResultRecommendation;
import de.rub.nds.scanner.core.report.rating.Recommendation;
import de.rub.nds.scanner.core.report.rating.Recommendations;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class RecommendationsSerializationIT {

    private static final Logger LOGGER = LogManager.getLogger();

    private Recommendations original;

    private Recommendations result;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    @BeforeEach
    public void setUp() throws JAXBException {

        List<Recommendation> propertyRecommendations = new LinkedList<>();
        original = new Recommendations(propertyRecommendations);
        List<PropertyResultRecommendation> recommendations = new LinkedList<>();
        PropertyResultRecommendation r =
                new PropertyResultRecommendation(
                        TestResults.TRUE, "SSLv2 is enabled", "Disable SSLv2");
        recommendations.add(r);

        propertyRecommendations.add(
                new Recommendation(TlsAnalyzedProperty.SUPPORTS_SSL_2, recommendations));
        original.setRecommendations(propertyRecommendations);

        writer = new StringWriter();
        context =
                JAXBContext.newInstance(
                        Recommendations.class,
                        Recommendation.class,
                        TlsAnalyzedProperty.class,
                        PropertyResultRecommendation.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        um = context.createUnmarshaller();
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testSerializeDeserializeSimple() throws Exception {
        m.marshal(original, writer);

        String xmlString = writer.toString();
        LOGGER.info(xmlString);

        um = context.createUnmarshaller();
        result = (Recommendations) um.unmarshal(new StringReader(xmlString));

        assertEquals(
                original.getRecommendations().size(),
                result.getRecommendations().size(),
                "Recommendation length check.");

        Recommendation oRecommendation = original.getRecommendations().get(0);
        Recommendation rRecommendation = result.getRecommendations().get(0);
        assertEquals(oRecommendation.getAnalyzedProperty(), rRecommendation.getAnalyzedProperty());

        PropertyResultRecommendation or = oRecommendation.getPropertyRecommendations().get(0);
        PropertyResultRecommendation rr = rRecommendation.getPropertyRecommendations().get(0);
        assertEquals(or.getShortDescription(), rr.getShortDescription());
        assertEquals(or.getHandlingRecommendation(), rr.getHandlingRecommendation());
    }
}
