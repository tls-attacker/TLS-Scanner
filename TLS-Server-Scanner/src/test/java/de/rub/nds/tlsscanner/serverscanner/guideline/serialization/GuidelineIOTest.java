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
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class GuidelineIOTest {
	private Guideline original, result;
	
	@Before
	public void setUp() {
		String testName = "guideline test name";
		String testLink = "www.guideline.test.link";
		
		@SuppressWarnings("rawtypes")
		List<GuidelineCheck> checks = new ArrayList<>();

        checks.add(new AnalyzedPropertyGuidelineCheck("Dies ist eine Empfehlung.",
            RequirementLevel.MAY, TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE));
        this.original = new Guideline(testName, testLink, checks);
	}
	
	@Test
	public void testDeSerializationSimple() throws IOException, JAXBException, XMLStreamException {	
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        GuidelineIO.write(stream, this.original);
        this.result = GuidelineIO.read(new ByteArrayInputStream(stream.toByteArray()));
		
        assertEquals("Influencer length check.", this.original.getChecks().size(),
                result.getChecks().size());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getRequirementLevel(),
                result.getChecks().get(0).getRequirementLevel());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getName(),
                result.getChecks().get(0).getName());  
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getId(),
                result.getChecks().get(0).getId());  
    
        GuidelineIO.write(Paths.get("src/main/resources/guideline/serializarion_test_simple.xml").toFile(), this.original);
        this.result = GuidelineIO.read(Paths.get("src/main/resources/guideline/serializarion_test_simple.xml").toFile());

        assertEquals("Influencer length check.", this.original.getChecks().size(),
                result.getChecks().size());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getRequirementLevel(),
                result.getChecks().get(0).getRequirementLevel());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getName(),
                result.getChecks().get(0).getName());
        assertEquals("Influencer length check.", this.original.getChecks().get(0).getId(),
                result.getChecks().get(0).getId());  
	}

	@After
	public void cleanUp() {
		File file = Paths.get("src/main/resources/guideline/serializarion_test_simple.xml").toFile();
		file.delete();
	}
}
