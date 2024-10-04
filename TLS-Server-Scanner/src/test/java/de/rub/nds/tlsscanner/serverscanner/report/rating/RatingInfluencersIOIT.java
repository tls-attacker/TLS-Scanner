/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.report.rating.RatingInfluencers;
import de.rub.nds.scanner.core.report.rating.RatingInfluencersIO;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class RatingInfluencersIOIT {

    /** Test of write method, of class RatingInfluencersIO. */
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testWrite_OutputStream_RatingInfluencers() throws Exception {
        RatingInfluencers ratingInfluencers = new RatingInfluencers(new LinkedList<>());
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        RatingInfluencersIO ratingInfluencersIO =
                new RatingInfluencersIO(TlsAnalyzedProperty.class);
        ratingInfluencersIO.write(stream, ratingInfluencers);
        byte[] byteArray = stream.toByteArray();
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray)) {
            ratingInfluencersIO.read(inputStream);
        }
    }
}
