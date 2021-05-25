/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.guideline.model.Guideline;

import javax.xml.bind.JAXB;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class GuidelineIO {

    public static final List<String> GUIDELINES = Arrays.asList("NIST.SP.800-52r2.xml", "BSI-TR-02102-2.xml");

    public static Guideline readGuideline(Path path) {
        return JAXB.unmarshal(path.toFile(), Guideline.class);
    }

    public static Guideline readGuideline(String resource) throws IOException {
        try (InputStream is = GuidelineIO.class.getResourceAsStream(resource)) {
            if (is == null) {
                throw new IOException("Resource not found. " + resource);
            }
            return JAXB.unmarshal(is, Guideline.class);
        }
    }

    private static Guideline readGuidelineUnchecked(String resource) {
        try (InputStream is = GuidelineIO.class.getResourceAsStream("/guideline/" + resource)) {
            if (is == null) {
                throw new IOException("Resource not found. " + resource);
            }
            return JAXB.unmarshal(is, Guideline.class);
        } catch (IOException exc) {
            throw new RuntimeException(exc);
        }
    }

    public static List<Guideline> readGuidelines(List<String> guidelines) throws IOException {
        try {
            return guidelines.stream().map(GuidelineIO::readGuidelineUnchecked).collect(Collectors.toList());
        } catch (RuntimeException exc) {
            if (exc.getCause() instanceof IOException) {
                throw (IOException) exc.getCause();
            } else {
                throw exc;
            }
        }
    }
}
