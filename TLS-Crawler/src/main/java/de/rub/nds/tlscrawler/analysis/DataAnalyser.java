/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.analysis;

import de.rub.nds.tlscrawler.config.AnalysisCommandConfig;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.Collection;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonDouble;

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
        persistenceProvider.clean(config.getDatabaseName(), config.getWorkspaceName());
        long totalAnswers = persistenceProvider.countDocuments(config.getDatabaseName(), config.getWorkspaceName(), new BsonDocument("result.report.ccaRequired", new BsonBoolean(true)));
        System.out.println("Total servers scanned: " + totalAnswers);
//        for (CipherSuite suite : CipherSuite.values()) {
//            System.out.println(suite.name());
//            System.out.println("Total:" + persistenceProvider.countDocuments(config.getDatabaseName(), config.getWorkspaceName(), new BsonDocument("result.report.cipherSuites", new BsonString(suite.name()))));
////            for (ProtocolVersion version : ProtocolVersion.values()) {
////                BsonDocument document = new BsonDocument();
////                document.put("result.report.versionSuitePairs.version", new BsonString(version.name()));
////                document.put("result.report.versionSuitePairs.cipherSuiteList", new BsonString(suite.name()));
////                long value = persistenceProvider.countDocuments(document);
////                if (value > 0) {
////                    System.out.println(version.name() + ":" + value);
////                }
////
////            }
//        }

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
        //Collection<SiteReport> siteReports = persistenceProvider.findSiteReports(config.getDatabaseName(), config.getWorkspaceName(), new BsonDocument("result.report.resultMap.VULNERABLE_TO_DIRECT_RACCOON", new BsonString("TRUE")));
//        Collection<SiteReport> siteReports = persistenceProvider.findSiteReports(config.getDatabaseName(), config.getWorkspaceName(), new BsonDocument("result.report.directRaccoonResultList.pValue", new BsonDocument("$lt", new BsonDouble(5.400433352483021e-60))));
//        for (SiteReport report : siteReports) {
//            SiteReportPrinter printer = new SiteReportPrinter(report, ScannerDetail.ALL, true);
//            StringBuilder builder = new StringBuilder();
//            printer.appendDirectRaccoonResults(builder);
//            System.out.println(report.getHost());
//            System.out.println(builder.toString());
//        }
    }
}
