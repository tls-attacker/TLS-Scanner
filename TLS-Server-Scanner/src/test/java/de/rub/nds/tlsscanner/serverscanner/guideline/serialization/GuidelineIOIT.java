/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.serialization;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.Guideline;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineIO;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.xml.stream.XMLStreamException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class GuidelineIOIT {
    private Guideline original, result;

    @BeforeEach
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
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testDeSerializationSimple(@TempDir File tempDir) throws IOException, JAXBException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        GuidelineIO.write(stream, this.original);
        this.result = GuidelineIO.read(new ByteArrayInputStream(stream.toByteArray()));

        assertEquals(this.original.getChecks().size(), result.getChecks().size(), "Influencer length check.");
        assertEquals(this.original.getChecks().get(0).getRequirementLevel(),
            result.getChecks().get(0).getRequirementLevel(), "Influencer length check.");
        assertEquals(this.original.getChecks().get(0).getName(), result.getChecks().get(0).getName(),
            "Influencer length check.");
        assertEquals(this.original.getChecks().get(0).getId(), result.getChecks().get(0).getId(),
            "Influencer length check.");

        File tempFile = new File(tempDir, "serializarion_test_simple.xml");
        GuidelineIO.write(tempFile, this.original);
        this.result = GuidelineIO.read(tempFile);

        assertEquals(this.original.getChecks().size(), result.getChecks().size(), "Influencer length check.");
        assertEquals(this.original.getChecks().get(0).getRequirementLevel(),
            result.getChecks().get(0).getRequirementLevel(), "Influencer length check.");
        assertEquals(this.original.getChecks().get(0).getName(), result.getChecks().get(0).getName(),
            "Influencer length check.");
        assertEquals(this.original.getChecks().get(0).getId(), result.getChecks().get(0).getId(),
            "Influencer length check.");
    }
}
