/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.rating;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.bind.JAXB;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactoryConfigurationException;
import org.xml.sax.SAXException;

public class RatingIO {

    public static void writeRecommendations(Recommendations r, File f) {
        try {
            JAXB.marshal(r, new FileOutputStream(f));
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex.getLocalizedMessage(), ex);
        }
    }

    public static void writeRecommendations(Recommendations r, OutputStream os) {
        ByteArrayOutputStream tempStream = new ByteArrayOutputStream();

        JAXB.marshal(r, tempStream);
        try {
            os.write(new String(tempStream.toByteArray()).getBytes());
        } catch (IOException ex) {
            throw new RuntimeException("Could not format XML");
        }
    }

    public static Recommendations readRecommendations(File f) {
        return JAXB.unmarshal(f, Recommendations.class);
    }

    public static Recommendations readRecommendations(InputStream is) {
        return JAXB.unmarshal(is, Recommendations.class);
    }

    public static void writeRatingInfluencers(RatingInfluencers ri, File f) {
        try {
            JAXB.marshal(ri, new FileOutputStream(f));
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex.getLocalizedMessage(), ex);
        }
    }

    public static void writeRatingInfluencers(RatingInfluencers ri, OutputStream os) {
        ByteArrayOutputStream tempStream = new ByteArrayOutputStream();

        JAXB.marshal(ri, tempStream);
        try {
            os.write(new String(tempStream.toByteArray()).getBytes());
        } catch (IOException ex) {
            throw new RuntimeException("Could not format XML");
        }
    }

    public static RatingInfluencers readRatingInfluencers(File f) {
        return JAXB.unmarshal(f, RatingInfluencers.class);
    }

    public static RatingInfluencers readRatingInfluencers(InputStream is) {
        return JAXB.unmarshal(is, RatingInfluencers.class);
    }
}
