/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencers;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class InfluencersSerializationTest {

    private static final Logger LOGGER = LogManager.getLogger(InfluencersSerializationTest.class);

    private RatingInfluencers original;

    private RatingInfluencers result;

    @Before
    public void setUp() throws JAXBException {
        LinkedList<RatingInfluencer> influencers = new LinkedList<>();

        original = new RatingInfluencers(influencers);
        RatingInfluencer i = new RatingInfluencer();
        i.setAnalyzedProperty(TlsAnalyzedProperty.SUPPORTS_SSL_2);
        i.addPropertyRatingInfluencer(new PropertyResultRatingInfluencer(TestResult.TRUE, -200, 500));
        i.addPropertyRatingInfluencer(new PropertyResultRatingInfluencer(TestResult.FALSE, 50));
        influencers.add(i);

        i = new RatingInfluencer();
        i.setAnalyzedProperty(TlsAnalyzedProperty.SUPPORTS_TLS_1_2);
        i.addPropertyRatingInfluencer(new PropertyResultRatingInfluencer(TestResult.TRUE, 100));
        influencers.add(i);

        original.setRatingInfluencers(influencers);
    }

    @Test
    public void testSerializeDeserializeSimple() throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        RatingInfluencersIO.write(stream, original);
        System.out.println(new String(stream.toByteArray()));
        result = RatingInfluencersIO.read(new ByteArrayInputStream(stream.toByteArray()));

        assertEquals("Influencer length check.", original.getRatingInfluencers().size(),
            result.getRatingInfluencers().size());

        RatingInfluencer oInfluencer = original.getRatingInfluencers().get(0);
        RatingInfluencer rInfluencer = result.getRatingInfluencers().get(0);
        assertEquals(oInfluencer.getAnalyzedProperty(), rInfluencer.getAnalyzedProperty());

        PropertyResultRatingInfluencer ori = oInfluencer.getPropertyRatingInfluencers().get(0);
        PropertyResultRatingInfluencer rri = rInfluencer.getPropertyRatingInfluencers().get(0);
        assertEquals(ori.getResult(), rri.getResult());
        assertEquals(ori.getInfluence(), rri.getInfluence(), 0.1);
        assertEquals(ori.getScoreCap(), rri.getScoreCap(), 0.1);
    }
}
