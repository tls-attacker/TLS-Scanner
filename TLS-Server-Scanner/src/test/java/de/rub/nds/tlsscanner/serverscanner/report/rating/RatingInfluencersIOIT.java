/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.report.rating.RatingInfluencers;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;

public class RatingInfluencersIOIT {

    /**
     * Test of write method, of class RatingInfluencersIO.
     */
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testWrite_OutputStream_RatingInfluencers() throws Exception {
        RatingInfluencers ratingInfluencers = new RatingInfluencers(new LinkedList<>());
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        RatingInfluencersIO.write(stream, ratingInfluencers);
        byte[] byteArray = stream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray);
        RatingInfluencers read = RatingInfluencersIO.read(inputStream);
    }

}
