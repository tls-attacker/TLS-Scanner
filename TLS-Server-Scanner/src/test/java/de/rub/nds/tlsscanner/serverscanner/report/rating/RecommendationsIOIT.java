/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.report.rating.Recommendations;
import de.rub.nds.scanner.core.report.rating.RecommendationsIO;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class RecommendationsIOIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testWrite_OutputStream_Recommendations() throws Exception {
        Recommendations recommendations = new Recommendations(new LinkedList<>());
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        RecommendationsIO recommendationsIO = new RecommendationsIO(TlsAnalyzedProperty.class);
        recommendationsIO.write(stream, recommendations);
        byte[] byteArray = stream.toByteArray();
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray)) {
            recommendationsIO.read(inputStream);
        }
    }
}
