/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.rating;

import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class RecommendationsSerializationTest {

    private static final Logger LOGGER = LogManager.getLogger(RecommendationsSerializationTest.class);

    private Recommendations original;

    private Recommendations result;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    @Before
    public void setUp() throws JAXBException {

        List<Recommendation> propertyRecommendations = new LinkedList<>();
        original = new Recommendations(propertyRecommendations);
        List<PropertyResultRecommendation> recommendations = new LinkedList<>();
        PropertyResultRecommendation r =
            new PropertyResultRecommendation(TestResult.TRUE, "SSLv2 is enabled", "Disable SSLv2");
        recommendations.add(r);

        propertyRecommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SSL_2, recommendations));
        original.setRecommendations(propertyRecommendations);

        writer = new StringWriter();
        context = JAXBContext.newInstance(Recommendations.class);
        m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        um = context.createUnmarshaller();
    }

    @Test
    public void testSerializeDeserializeSimple() throws Exception {
        m.marshal(original, writer);

        String xmlString = writer.toString();
        LOGGER.info(xmlString);

        um = context.createUnmarshaller();
        result = (Recommendations) um.unmarshal(new StringReader(xmlString));

        assertEquals("Recommendation length check.", original.getRecommendations().size(),
            result.getRecommendations().size());

        Recommendation oRecommendation = original.getRecommendations().get(0);
        Recommendation rRecommendation = result.getRecommendations().get(0);
        assertEquals(oRecommendation.getAnalyzedProperty(), rRecommendation.getAnalyzedProperty());

        PropertyResultRecommendation or = oRecommendation.getPropertyRecommendations().get(0);
        PropertyResultRecommendation rr = rRecommendation.getPropertyRecommendations().get(0);
        assertEquals(or.getShortDescription(), rr.getShortDescription());
        assertEquals(or.getHandlingRecommendation(), rr.getHandlingRecommendation());
    }

}
