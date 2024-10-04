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
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencers;
import de.rub.nds.scanner.core.report.rating.RatingInfluencersIO;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class InfluencersSerializationIT {

    private RatingInfluencers original;

    private RatingInfluencers result;

    @BeforeEach
    public void setUp() {
        LinkedList<RatingInfluencer> influencers = new LinkedList<>();

        original = new RatingInfluencers(influencers);
        RatingInfluencer i = new RatingInfluencer();
        i.setAnalyzedProperty(TlsAnalyzedProperty.SUPPORTS_SSL_2);
        i.addPropertyRatingInfluencer(
                new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 500));
        i.addPropertyRatingInfluencer(new PropertyResultRatingInfluencer(TestResults.FALSE, 50));
        influencers.add(i);

        i = new RatingInfluencer();
        i.setAnalyzedProperty(TlsAnalyzedProperty.SUPPORTS_TLS_1_2);
        i.addPropertyRatingInfluencer(new PropertyResultRatingInfluencer(TestResults.TRUE, 100));
        influencers.add(i);

        original.setRatingInfluencers(influencers);
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testSerializeDeserializeSimple() throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        RatingInfluencersIO ratingInfluencersIO =
                new RatingInfluencersIO(TlsAnalyzedProperty.class);
        ratingInfluencersIO.write(stream, original);
        try (ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(stream.toByteArray())) {
            result = ratingInfluencersIO.read(byteArrayInputStream);
        }

        assertEquals(
                original.getRatingInfluencers().size(),
                result.getRatingInfluencers().size(),
                "Influencer length check.");

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
