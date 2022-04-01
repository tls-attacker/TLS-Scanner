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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class RatingInfluencersIOTest {

    public RatingInfluencersIOTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of write method, of class RatingInfluencersIO.
     */
    @Test
    public void testWrite_OutputStream_RatingInfluencers() throws Exception {
        RatingInfluencers ratingInfluencers = new RatingInfluencers(new LinkedList<>());
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        RatingInfluencersIO.write(stream, ratingInfluencers);
        byte[] byteArray = stream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray);
        RatingInfluencers read = RatingInfluencersIO.read(inputStream);
    }

}
