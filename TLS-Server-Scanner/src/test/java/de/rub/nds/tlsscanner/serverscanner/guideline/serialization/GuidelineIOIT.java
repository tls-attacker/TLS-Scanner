/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.serialization;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.guideline.Guideline;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineIO;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.JAXBException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class GuidelineIOIT {
    private Guideline<ServerReport> original, result;

    private GuidelineIO guidelineIO;

    @BeforeEach
    public void setUp() throws JAXBException {
        String testName = "guideline test name";
        String testLink = "www.guideline.test.link";

        List<GuidelineCheck<ServerReport>> checks = new ArrayList<>();

        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Dies ist eine Empfehlung.",
                        RequirementLevel.MAY,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                        TestResults.TRUE));
        this.original = new Guideline<>(testName, testLink, checks);
        this.guidelineIO = new GuidelineIO(TlsAnalyzedProperty.class);
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testDeSerializationSimple(@TempDir File tempDir)
            throws IOException, JAXBException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        guidelineIO.write(stream, this.original);
        this.result =
                (Guideline<ServerReport>)
                        guidelineIO.read(new ByteArrayInputStream(stream.toByteArray()));

        assertEquals(
                this.original.getChecks().size(),
                result.getChecks().size(),
                "Influencer length check.");
        assertEquals(
                this.original.getChecks().get(0).getRequirementLevel(),
                result.getChecks().get(0).getRequirementLevel(),
                "Influencer length check.");
        assertEquals(
                this.original.getChecks().get(0).getName(),
                result.getChecks().get(0).getName(),
                "Influencer length check.");
        assertEquals(
                this.original.getChecks().get(0).toString(),
                result.getChecks().get(0).toString(),
                "Influencer length check.");

        File tempFile = new File(tempDir, "serializarion_test_simple.xml");
        guidelineIO.write(tempFile, this.original);
        this.result = (Guideline<ServerReport>) guidelineIO.read(tempFile);

        assertEquals(
                this.original.getChecks().size(),
                result.getChecks().size(),
                "Influencer length check.");
        assertEquals(
                this.original.getChecks().get(0).getRequirementLevel(),
                result.getChecks().get(0).getRequirementLevel(),
                "Influencer length check.");
        assertEquals(
                this.original.getChecks().get(0).getName(),
                result.getChecks().get(0).getName(),
                "Influencer length check.");
        assertEquals(
                this.original.getChecks().get(0).toString(),
                result.getChecks().get(0).toString(),
                "Influencer length check.");
    }
}
