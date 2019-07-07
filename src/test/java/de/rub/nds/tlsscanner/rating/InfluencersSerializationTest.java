/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

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

public class InfluencersSerializationTest {

    private static final Logger LOGGER = LogManager.getLogger(InfluencersSerializationTest.class);

    private Influencers original;

    private Influencers result;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    @Before
    public void setUp() throws JAXBException {
        original = new Influencers();
        List<Influencer> influencers = new LinkedList<>();
        Influencer i = new Influencer(AnalyzedProperty.SSL_2, TestResult.TRUE, -200.0, 500.0);
        influencers.add(i);
        original.setInfluencers(influencers);

        writer = new StringWriter();
        context = JAXBContext.newInstance(Influencers.class);
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
        result = (Influencers) um.unmarshal(new StringReader(xmlString));
        
        assertEquals("Influencer length check.", original.getInfluencers().size(), result.getInfluencers().size());
        Influencer oInfluencer = original.getInfluencers().get(0);
        Influencer rInfluencer = result.getInfluencers().get(0);
        
        assertEquals(oInfluencer.getAnalyzedProperty(), rInfluencer.getAnalyzedProperty());
        assertEquals(oInfluencer.getResult(), rInfluencer.getResult());
        assertEquals(oInfluencer.getInfluence(), rInfluencer.getInfluence(), 0.1);
        assertEquals(oInfluencer.getScoreCap(), rInfluencer.getScoreCap(), 0.1);
    }
    
}
