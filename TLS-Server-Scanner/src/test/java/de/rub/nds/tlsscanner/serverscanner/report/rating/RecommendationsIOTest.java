/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.report.rating.Recommendations;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;
import org.junit.Test;

public class RecommendationsIOTest {

    @Test
    public void testWrite_OutputStream_Recommendations() throws Exception {
        Recommendations recommendations = new Recommendations(new LinkedList<>());
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        RecommendationsIO.write(stream, recommendations);
        byte[] byteArray = stream.toByteArray();
        System.out.println(new String(byteArray));
        ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray);
        Recommendations read = RecommendationsIO.read(inputStream);
    }
}
