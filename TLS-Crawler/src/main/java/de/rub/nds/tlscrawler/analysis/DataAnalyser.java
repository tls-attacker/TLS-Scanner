/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.analysis;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlscrawler.config.AnalysisCommandConfig;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.SiteReportPrinter;
import java.util.Collection;
import org.bson.BsonDocument;
import org.bson.BsonString;

/**
 *
 * @author robert
 */
public class DataAnalyser {

    private AnalysisCommandConfig config;

    private IPersistenceProvider persistenceProvider;

    public DataAnalyser(AnalysisCommandConfig config, IPersistenceProvider persistenceProvider) {
        this.config = config;
        this.persistenceProvider = persistenceProvider;
    }

    public AnalysisCommandConfig getConfig() {
        return config;
    }

    public void analyze() {
        persistenceProvider.init(config.getDatabaseName(), config.getWorkspaceName());
        persistenceProvider.clean();
        long totalAnswers = persistenceProvider.countDocuments(new BsonDocument());
        System.out.println("Total servers scanned: " + totalAnswers);
        for (CipherSuite suite : CipherSuite.values()) {
            System.out.println(suite.name());
            System.out.println("Total:" + persistenceProvider.countDocuments(new BsonDocument("result.report.cipherSuites", new BsonString(suite.name()))));
//            for (ProtocolVersion version : ProtocolVersion.values()) {
//                BsonDocument document = new BsonDocument();
//                document.put("result.report.versionSuitePairs.version", new BsonString(version.name()));
//                document.put("result.report.versionSuitePairs.cipherSuiteList", new BsonString(suite.name()));
//                long value = persistenceProvider.countDocuments(document);
//                if (value > 0) {
//                    System.out.println(version.name() + ":" + value);
//                }
//
//            }
        }

//        for (AnalyzedProperty property : AnalyzedProperty.values()) {
//            System.out.println("#############");
//            System.out.println("Property:" + property.name());
//            for (TestResult result : TestResult.values()) {
//                long countedDocuments = persistenceProvider.countDocuments(new BsonDocument("result.report.resultMap." + property.name(), new BsonString(result.name())));
//                if (countedDocuments != 0) {
//                    System.out.println(result.name() + ":" + countedDocuments);
//                }
////          
//            }
//        }
//
        Collection<SiteReport> siteReports = persistenceProvider.findSiteReports(new BsonDocument("result.report.resultMap.VULNERABLE_TO_DIRECT_RACCOON", new BsonString("TRUE")));
        for (SiteReport report : siteReports) {
            SiteReportPrinter printer = new SiteReportPrinter(report, ScannerDetail.DETAILED, false);
            System.out.println(printer.getFullReport());
        }
    }
}
