package de.rub.nds.tlsscanner.serverscanner.report;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.math.BigDecimal;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ObjectNode;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.serverscanner.TlsScanner;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.converter.Asn1CertificateSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.Asn1EncodableSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.ByteArraySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CertificateSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CustomDhPublicKeySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CustomDsaPublicKeySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CustomEcPublicKeySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.CustomRsaPublicKeySerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.HttpsHeaderSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.PointSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.ResponseFingerprintSerializer;
import de.rub.nds.tlsscanner.serverscanner.converter.VectorSerializer;

public class SiteReportSerializationTest {
	private static SiteReport report;
	private static ScannerConfig config;

	@BeforeClass
	public static void setUpClass() {
		config = new ScannerConfig(new GeneralDelegate());
		config.getClientDelegate().setHost("tls-scanner.cs.uni-paderborn.de");
		config.setScanDetail(ScannerDetail.NORMAL);
		config.setReportDetail(ScannerDetail.ALL);
		config.setOverallThreads(100);
		config.setParallelProbes(100);
		config.setNoColor(true);
		TlsScanner scanner = new TlsScanner(config);
		report = scanner.scan();
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

	@Test
	public void testJSONWriter() {
		SiteReportJSONprinter jsonReport = new SiteReportJSONprinter(report, config.getReportDetail());
		ObjectNode jsonResult = jsonReport.getJSONReport();
		assertNotNull(jsonResult.get("hostname").toString());
	}

	@SuppressWarnings("unused")
	@Test
	public void testCralwerSerializers() {
		ObjectMapper mapper = new ObjectMapper();

		SimpleModule module = new SimpleModule();
		module.addSerializer(new ByteArraySerializer());
		module.addSerializer(new ResponseFingerprintSerializer());
		module.addSerializer(new CertificateSerializer());
		module.addSerializer(new Asn1CertificateSerializer());
		module.addSerializer(new CustomDhPublicKeySerializer());
		module.addSerializer(new CustomEcPublicKeySerializer());
		module.addSerializer(new CustomRsaPublicKeySerializer());
		module.addSerializer(new CustomDsaPublicKeySerializer());
		module.addSerializer(new VectorSerializer());
		module.addSerializer(new PointSerializer());
		module.addSerializer(new HttpsHeaderSerializer());
		module.addSerializer(new Asn1EncodableSerializer());

		mapper.registerModule(module);
		mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
		mapper.configOverride(BigDecimal.class).setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));

		try {
			String reportJson = mapper.writeValueAsString(report);
		} catch (JsonProcessingException e) {
			fail("Exception occured");
		}
	}

}
