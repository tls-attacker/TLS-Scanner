/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.serialization;

import static org.junit.Assert.assertEquals;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.Guideline;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineIO;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class GuidelineIOTest {
    private Guideline original, result;

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Before
    public void setUp() {
        String testName = "guideline test name";
        String testLink = "www.guideline.test.link";

        @SuppressWarnings("rawtypes")
        List<GuidelineCheck> checks = new ArrayList<>();

        checks.add(new AnalyzedPropertyGuidelineCheck("Dies ist eine Empfehlung.", RequirementLevel.MAY,
            TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE));
        this.original = new Guideline(testName, testLink, checks);
    }

    @Test
    public void testDeSerializationSimple() throws IOException, JAXBException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        GuidelineIO.write(stream, this.original);
        this.result = GuidelineIO.read(new ByteArrayInputStream(stream.toByteArray()));

        assertEquals("Influencer length check.", this.original.getChecks().size(), result.getChecks().size());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getRequirementLevel(),
            result.getChecks().get(0).getRequirementLevel());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getName(),
            result.getChecks().get(0).getName());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getId(),
            result.getChecks().get(0).getId());

        File tempFile = tempDir.newFile("serializarion_test_simple.xml");
        GuidelineIO.write(tempFile, this.original);
        this.result = GuidelineIO.read(tempFile);

        assertEquals("Influencer length check.", this.original.getChecks().size(), result.getChecks().size());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getRequirementLevel(),
            result.getChecks().get(0).getRequirementLevel());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getName(),
            result.getChecks().get(0).getName());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getId(),
            result.getChecks().get(0).getId());
    }
}
