/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.samples;

import com.beust.jcommander.internal.Lists;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.wrapper.MutableInt;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.persistence.MongoPersistenceProvider;
import de.rub.nds.tlscrawler.utility.ITuple;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import static java.lang.System.exit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonRegularExpression;
import org.bson.BsonString;
import org.bson.Document;
import org.jgrapht.UndirectedGraph;
import org.jgrapht.ext.DOTExporter;
import org.jgrapht.ext.StringEdgeNameProvider;
import org.jgrapht.ext.StringNameProvider;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;

/**
 * Sample script fetching a database record and parsing it into a TLS Scanner
 * Site Report Object.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ReportFetching {

    private static HashMap<EqualityError, MutableInt> errorMap = new HashMap<>();
    private static HashMap<CipherSuite, MutableInt> suiteMap = new HashMap<>();
    private static HashMap<ProtocolVersion, MutableInt> versionMap = new HashMap<>();
    private static ArrayList<Report> reportList = new ArrayList<>();
    private static HashMap<CipherSuite, MutableInt> allSuiteMap = new HashMap<>();
    private static int onlyCbcTotal = 0;
    private static int onlyCbcVuln = 0;
    private static int onlyCbcAllVuln = 0;
    private static int vulnTotal = 0;

    public static void main(String... args) {

        // SETUP
        String mongoHost = "cloud.nds.rub.de";//"192.168.129.133";
        int mongoPort = 42133;
        String mongoUser = "janis";
        String mongoAuthSource = "admin";
        String mongoPass = "myStrongPass123!";
        String mongoWorkspace = "TLSC-alexa-8";
        System.out.println("Workspace: " + mongoWorkspace);
        // EXEC
        ServerAddress addr = new ServerAddress(mongoHost, mongoPort);
        MongoCredential cred = MongoCredential.createCredential(
                mongoUser,
                mongoAuthSource,
                mongoPass.toCharArray());
        pp = new MongoPersistenceProvider(addr, cred);
        pp.init(mongoWorkspace);
        MongoClient mongoClient = new MongoClient(new ServerAddress(mongoHost, mongoPort), Arrays.asList(cred));
        MongoDatabase database = mongoClient.getDatabase(mongoWorkspace);
        MongoCollection<Document> collection = database.getCollection("scans");
//        FindIterable<Document> allDocs = collection.find();
//        for (Document d : allDocs) {
//            boolean supportsGcm = d.getBoolean("results.tls_scan.ciphers.supportsAeadCiphers", true);
//            boolean supportsCbc = d.getBoolean("results.tls_scan.ciphers.supportsBlockCiphers", true);
//            boolean vulnerable = d.getBoolean("results.tls_scan.attacks.paddingOracleVulnerable", true);
//            
//            if (supportsCbc && !supportsGcm) {
//                onlyCbcTotal++;
//            }
//            if (supportsCbc && !supportsGcm && vulnerable) {
//                onlyCbcVuln++;
//            }
//            if(vulnerable)
//            {
//                vulnTotal++;
//            }
//            updateCipherSuiteStats(d);
//        }
        System.out.println("Only Cbc Total:" + onlyCbcTotal);
        System.out.println("Only Cbc and Vuln:" + onlyCbcVuln);
        HashMap<CipherSuite, Integer> csMap = new HashMap<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.isCBC() && !suite.isExport()) {
                double counter = collection.count(new BsonDocument("results.tls_scan.ciphers.cipherSuites", new BsonString(suite.name())));
                csMap.put(suite, (int) counter);
            }
        }
        FindIterable<Document> find = collection.find(new BsonDocument("results.tls_scan.attacks.paddingOracleVulnerable", new BsonBoolean(true)));
        double notVulnCounter = collection.count(new BsonDocument("results.tls_scan.attacks.paddingOracleVulnerable", new BsonBoolean(false)));
        double vulnCounter = collection.count(new BsonDocument("results.tls_scan.attacks.paddingOracleVulnerable", new BsonBoolean(true)));
        double serverIsAlive = collection.count(new BsonDocument("results.tls_scan.serverIsAlive", new BsonBoolean(true)));
        double speaksTlsCounter = collection.count(new BsonDocument("results.tls_scan.supportsSslTls", new BsonBoolean(true)));
        System.out.println("Sever is alive:" + serverIsAlive);
        System.out.println("Sever speaks SSL/TLS:" + speaksTlsCounter);
        System.out.println("Vuln Hosts:" + vulnCounter);
        System.out.println("Not Vuln Hosts:" + notVulnCounter);

        System.out.println("Percent Vuln:" + ((double) (Math.round((vulnCounter / speaksTlsCounter) * 10000))) / 100 + "%");
        System.out.println("Suites:");
        for (CipherSuite suite : allSuiteMap.keySet()) {
            System.out.println("Suite:" + suite.name() + ": " + allSuiteMap.get(suite).getValue());
        }
        FindIterable<Document> projection = find.projection(new BsonDocument("targetIp", new BsonInt32(1)));
        for (Document d : projection) {
            String id = d.getString("_id");
            String host = d.getString("targetIp");
            System.out.println(host);
            IScanTask task = pp.getScanTask(id);
            Collection<IScanResult> results = task.getResults();
            for (IScanResult result : results) {
                List<ITuple<String, Object>> contents = result.getContents();
                for (ITuple<String, Object> tuple : contents) {
                    if (tuple.getFirst().equals("host")) {
                        host = tuple.getSecond().toString();
                    }
                    if (tuple.getFirst().equals("paddingOracle")) {
                        ScanResult paddingOracleResults = (ScanResult) tuple.getSecond();
                        List<ITuple<String, Object>> scanResultList = paddingOracleResults.getContents();
                        for (ITuple<String, Object> sth : scanResultList) {
                            if (sth.getFirst().equals("paddingOracleResults")) {
                                //now we have all padding oracle scan results
                                processScanResultsList(host, ((List) sth.getSecond()));
                            }
                        }
                    }
                }
            }
        }

        System.out.println("----ErrorTypes----");
        for (EqualityError error : EqualityError.values()) {
            if (errorMap.containsKey(error)) {
                System.out.println("" + error.name() + ": " + errorMap.get(error).getValue());
            }
        }

        System.out.println("----Vuln Suites----");
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.isExport()) {
                continue;
            }
            if (suiteMap.containsKey(suite)) {
                System.out.println("" + suite.name() + ": " + suiteMap.get(suite).getValue() + "/" + csMap.get(suite) + " - " + ((double)suiteMap.get(suite).getValue()) / ((double)csMap.get(suite)));
            }
        }
        exit(1);
        System.out.println("----Vuln Version----");
        for (ProtocolVersion version : ProtocolVersion.values()) {
            if (versionMap.containsKey(version)) {
                System.out.println("" + version.name() + ": " + versionMap.get(version).getValue());
            }
        }
        int numberAllVuln = 0;
        List<Report> uniqueReports = new LinkedList<>();
        for (Report r : reportList) {
            if (r.allAreVulnerable()) {
                numberAllVuln++;
            }
        }
        System.out.println("#all vuln: " + numberAllVuln);


        int notAllVersionVuln = 0;
        int notAllKeyExchangeVuln = 0;
        System.out.println("Not all KE Vuln:");
        for (Report r : reportList) {
            boolean found = false;

            for (CsvReport csv : r.getVulnerabilityList()) {
                if (found) {
                    break;
                }
                if (csv.isVulnerable() && !csv.isScanError() && !csv.isShaky()) {
                    for (CsvReport csv2 : r.getVulnerabilityList()) {
                        if (!csv2.isVulnerable() && !csv2.isScanError() && !csv2.isShaky()) {
                            if (csv.getSuite().name().split("WITH")[1] == csv2.getSuite().name().split("WITH")[1]) {
                                if (csv.getVersion() == csv2.getVersion()) {
                                    System.out.println(r.getHost());
                                    notAllKeyExchangeVuln++;
                                    found = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        System.out.println("Total:" + notAllKeyExchangeVuln);

        System.out.println("Not all Versions Vuln:");
        for (Report r : reportList) {
            Set<String> vulnCiphers = new HashSet<>();

            for (CsvReport csv : r.getVulnerabilityList()) {
                if (csv.isVulnerable() && !csv.isShaky() && !csv.isScanError()) {
                    vulnCiphers.add(csv.getSuite().name());
                }
            }

            for (CsvReport csv : r.getVulnerabilityList()) {
                if (!csv.isVulnerable() && !csv.isShaky() && !csv.isScanError()) {
                    if (vulnCiphers.contains(csv.getSuite().name())) {
                        System.out.println(r.getHost());
                        notAllVersionVuln++;
                        break;
                    }
                }
            }
        }

        System.out.println(
                "Total:" + notAllVersionVuln);

        int onlyOneVulnerability = 0;
        int multipleVulnerabilitys = 0;

        Set<List<String>> vulnSet = new HashSet<>();

        for (Report report : reportList) {
            if (report.vulnCsvAreEqual()) {
                onlyOneVulnerability++;

                for (CsvReport csv : report.getVulnerabilityList()) {
                    if (csv.isVulnerable() && !csv.isScanError() && !csv.isShaky()) {
                        List<String> newVulnMap = new LinkedList<>();
                        for (int i = 0; i < 25; i++) {
                            newVulnMap.add(csv.getResponseMap().get(i).split("paddingVector")[0]);
                        }
                        vulnSet.add(newVulnMap);
                    }
                }
            } else {
                multipleVulnerabilitys++;
            }

        }

        System.out.println(
                "One:" + onlyOneVulnerability);
        System.out.println(
                "Multiple:" + multipleVulnerabilitys);
        System.out.println(
                "#UniqueVulnMaps:" + vulnSet.size());
        ArrayList<List<String>> vulnList = new ArrayList<>();
        ArrayList<List<String>> vulnHostList = new ArrayList<>();

        vulnList.addAll(vulnSet);
        ArrayList<MutableInt> vulnTypeCounter = new ArrayList<>();
        for (List l : vulnList) {
            vulnTypeCounter.add(new MutableInt(0));
            vulnHostList.add(new LinkedList<>());
        }

        for (Report report : reportList) {
            if (report.vulnCsvAreEqual()) {
                int indexOf = -1;
                for (CsvReport csv : report.getVulnerabilityList()) {
                    if (csv.isVulnerable() && !csv.isScanError() && !csv.isShaky()) {
                        List<String> newVulnMap = new LinkedList<>();
                        for (int i = 0; i < 25; i++) {
                            newVulnMap.add(csv.getResponseMap().get(i).split("paddingVector")[0]);
                        }
                        indexOf = vulnList.indexOf(newVulnMap);
                        break;
                    }
                }
                if (indexOf == -1) {
                    System.out.println("opps");
                    continue;
                }
                vulnTypeCounter.get(indexOf).addValue(1);
                vulnHostList.get(indexOf).add(report.getHost());
            }
        }
        for (int i = 0; i < vulnList.size(); i++) {
            List<String> list = vulnList.get(i);
            System.out.println("------------------" + i + "------------------");
            System.out.println("#" + vulnTypeCounter.get(i).getValue());
            System.out.println();
            for (String s : list) {
                System.out.println(s.split("paddingVector")[0]);
            }
            System.out.println();
            System.out.println("Ips:");
            for (String ip : vulnHostList.get(i)) {
                System.out.println(ip);
            }
            List<Report> subReportList = new LinkedList<>();
            for (Report r : reportList) {
                List<String> vulnIpList = vulnHostList.get(i);
                for (String ip : vulnIpList) {
                    if (ip.replace(":443", "").equals(r.getHost().replace(":443", ""))) {
                        boolean clean = true;
                        for (CsvReport csv : r.getVulnerabilityList()) {
                            if (csv.isScanError() || csv.isShaky()) {
                                clean = false;
                            }
                        }
                        if (true || clean) {
                            subReportList.add(r);
                        }
                        break;
                    }
                }
            }
            // createSoftGraph(subReportList, "graphGroup" + i);

        }

        //System.out.println(
        //        "Searching for minimum vectors");
        //System.out.println(createMustHaveListBottomUp());
        System.out.println(
                "Combined Graph");
        //createCombinedGraph(reportList, "combined_full");
        System.out.println("Full");
        createGraph(reportList, "full");

    }
    private static MongoPersistenceProvider pp;

    private static boolean uniqueContained(List<Report> uniqueReportList, Report r) {
        for (Report report : uniqueReportList) {
            if (report.allVulnEqual(r)) {
                return true;
            }
        }
        return false;
    }

    private static void processScanResultsList(String host, List<ScanResult> scanResultList) {
        Set<String> vulnerableSuffix = new HashSet<>();
        Set<String> notVulnSuffix = new HashSet<>();
        Report report = new Report(host);
        for (ScanResult result : scanResultList) {
            List<ITuple<String, Object>> resultContents = result.getContents();
            EqualityError equailityError = null;
            CipherSuite suite = null;
            ProtocolVersion version = null;
            Boolean vulnerable = null;
            Boolean shaky = null;
            Boolean hasError = null;
            List<String> responseMap = null;

            for (ITuple<String, Object> tempTuple : resultContents) {
                if (tempTuple.getFirst().equals("getEqualityError")) {
                    equailityError = EqualityError.valueOf((String) (tempTuple.getSecond()));
                }
                if (tempTuple.getFirst().equals("suite")) {
                    suite = CipherSuite.valueOf(tempTuple.getSecond().toString());
                }
                if (tempTuple.getFirst().equals("version")) {
                    version = ProtocolVersion.valueOf(tempTuple.getSecond().toString());
                }
                if (tempTuple.getFirst().equals("vulnerable")) {
                    vulnerable = (Boolean) tempTuple.getSecond();
                }
                if (tempTuple.getFirst().equals("shaky")) {
                    shaky = (Boolean) tempTuple.getSecond();
                }
                if (tempTuple.getFirst().equals("scanError")) {
                    hasError = (Boolean) tempTuple.getSecond();
                }
                if (tempTuple.getFirst().equals("responseMap")) {
                    responseMap = (List<String>) tempTuple.getSecond();
                }
            }
            if (!shaky && vulnerable) {

                if (errorMap.containsKey(equailityError)) {
                    MutableInt get = errorMap.get(equailityError);
                    get.addValue(1);
                } else {
                    errorMap.put(equailityError, new MutableInt(1));
                }

                if (suiteMap.containsKey(suite)) {
                    MutableInt get = suiteMap.get(suite);
                    get.addValue(1);
                } else {
                    suiteMap.put(suite, new MutableInt(1));
                }

                if (versionMap.containsKey(version)) {
                    MutableInt get = versionMap.get(version);
                    get.addValue(1);
                } else {
                    versionMap.put(version, new MutableInt(1));
                }

                String splitSuite[] = suite.name().split("_WITH");
                vulnerableSuffix.add(splitSuite[1]);
            } else if (!shaky && !vulnerable) {
                String splitSuite[] = suite.name().split("_WITH");
                notVulnSuffix.add(splitSuite[1]);
            }
            report.addCsvReport(new CsvReport(suite, version, vulnerable, shaky, hasError, responseMap));

        }
        reportList.add(report);

    }

    public static void createSoftGraph(List<Report> tempReportList, String name) {
        UndirectedGraph<String, DefaultEdge> graph = new SimpleGraph<>(DefaultEdge.class);
        UndirectedGraph<String, DefaultEdge> invertedGraph = new SimpleGraph<>(DefaultEdge.class);

        for (Report report : tempReportList) {
            //Create node
            graph.addVertex("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
            invertedGraph.addVertex("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));

        }
        System.out.println("Creating Graph");

        int i = 0;

        for (Report report : tempReportList) {
            i++;
            for (Report otherReport : tempReportList) {
                if (report != otherReport) {
                    if (report.softContradicts(otherReport)) {
                        graph.addEdge("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"), "Host_" + otherReport.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
                    } else {
                        if (otherReport != report) {
                            invertedGraph.addEdge("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"), "Host_" + otherReport.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
                        }
                    }
                }
            }
            System.out.println(i + "/" + tempReportList.size());
        }

        System.out.println("Writing Graph");

        DOTExporter exporter = new DOTExporter(new StringNameProvider<String>(), new StringNameProvider<String>(), new StringEdgeNameProvider<String>());
        try {
            exporter.export(new FileWriter(new File(name + ".dot")), graph);
            exporter.export(new FileWriter(new File(name + "_inv.dot")), invertedGraph);

        } catch (IOException ex) {
            Logger.getLogger(ReportFetching.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Searching Coloring");
        int colouringNumber = GraphColouring.getColouringNumber(graph);
        System.out.println("Couloring:" + colouringNumber);
        System.out.println("Searching Clique:");

//        CliqueFinder finder = new CliqueFinder(graph);
//        System.out.println("clique:" + finder.getMaxCliqueSize());
//        System.out.println("Searching Clique:");
//
//        CliqueFinder finder = new CliqueFinder(graph);
//        List<Set<String>> allMaximalCliques = finder.getMaxCliqueSize();
//        for (Set<String> clique : allMaximalCliques) {
//            System.out.println(clique);
//        }
    }

    public static void createGraph(List<Report> tempReportList, String name) {
        UndirectedGraph<String, DefaultEdge> graph = new SimpleGraph<>(DefaultEdge.class);
        UndirectedGraph<String, DefaultEdge> invertedGraph = new SimpleGraph<>(DefaultEdge.class);

        for (Report report : tempReportList) {
            //Create node
            graph.addVertex("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
            invertedGraph.addVertex("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));

        }
        System.out.println("Creating Graph");

        int i = 0;

        for (Report report : tempReportList) {
            i++;
            for (Report otherReport : tempReportList) {
                if (report != otherReport) {
                    if (report.contradicts(otherReport)) {
                        graph.addEdge("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"), "Host_" + otherReport.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
                    } else {
                        if (otherReport != report) {
                            invertedGraph.addEdge("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"), "Host_" + otherReport.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
                        }
                    }
                }
            }
            System.out.println(i + "/" + tempReportList.size());
        }

        System.out.println("Writing Graph");

        DOTExporter exporter = new DOTExporter(new StringNameProvider<String>(), new StringNameProvider<String>(), new StringEdgeNameProvider<String>());
        try {
            exporter.export(new FileWriter(new File(name + ".dot")), graph);
            exporter.export(new FileWriter(new File(name + "_inv.dot")), invertedGraph);

        } catch (IOException ex) {
            Logger.getLogger(ReportFetching.class
                    .getName()).log(Level.SEVERE, null, ex);
        }

        System.out.println("Searching Clique:");

//        CliqueFinder finder = new CliqueFinder(graph);
//        System.out.println("clique:" + finder.getMaxCliqueSize());
//        List<Set<String>> allMaximalCliques = finder.getMaxCliqueSize();
//        for (Set<String> clique : allMaximalCliques) {
//            System.out.println(clique);
//        }
    }

    public static void createCombinedGraph(List<Report> tempReportList, String name) {
        UndirectedGraph<String, DefaultEdge> graph = new SimpleGraph<>(DefaultEdge.class);
        UndirectedGraph<String, DefaultEdge> invertedGraph = new SimpleGraph<>(DefaultEdge.class);
        Set<Report> reportSet = new HashSet<>();

        for (Report report : tempReportList) {
            reportSet.add(report);
        }
        for (Report report : reportSet) {
            //Create node
            graph.addVertex("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
            invertedGraph.addVertex("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));

        }
        System.out.println("Creating Graph");

        int i = 0;

        for (Report report : reportSet) {
            i++;
            for (Report otherReport : reportSet) {
                if (report != otherReport) {
                    if (report.contradicts(otherReport)) {
                        graph.addEdge("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"), "Host_" + otherReport.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
                    } else {
                        if (otherReport != report) {
                            invertedGraph.addEdge("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"), "Host_" + otherReport.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
                        }
                    }
                }
            }
            System.out.println(i + "/" + reportSet.size());
        }

        System.out.println("Writing Graph");

        DOTExporter exporter = new DOTExporter(new StringNameProvider<String>(), new StringNameProvider<String>(), new StringEdgeNameProvider<String>());
        try {
            exporter.export(new FileWriter(new File(name + ".dot")), graph);
            exporter.export(new FileWriter(new File(name + "_inv.dot")), invertedGraph);

        } catch (IOException ex) {
            Logger.getLogger(ReportFetching.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Searching Coloring");
        int colouringNumber = GraphColouring.getColouringNumber(graph);
        System.out.println("Couloring:" + colouringNumber);
        System.out.println("Searching Clique:");

//        CliqueFinder finder = new CliqueFinder(graph);
//        System.out.println("clique:" + finder.getMaxCliqueSize());
    }

    public static void testDel() {
        List<Integer> intList = new LinkedList<>();
        for (int i = 0; i < 26; i++) {
            intList.add(i);
        }

        List<Integer> createMustHaveList = createMustHaveListTopDown(intList, reportList);
        for (Integer i : createMustHaveList) {
            System.out.println("Musthave: " + i);
        }
    }

    public static List<Integer> createMustHaveListBottomUp() {

        List<List<Integer>> toTestLists = new LinkedList<>();
        extendLists(toTestLists);
        List<Integer> solution = null;
        int solutionLenght = 1;
        while (solution == null) {
            solutionLenght++;
            System.out.println("Testing:" + solutionLenght);
            extendLists(toTestLists);
            solution = testForSolution(toTestLists);
        }
        return solution;
    }

    public static void extendLists(List<List<Integer>> lists) {
        if (lists.isEmpty()) {
            for (int i = 0; i < 26; i++) {
                List<Integer> tempList = new LinkedList<>();
                tempList.add(i);
                lists.add(tempList);
            }
        } else {
            List<List<Integer>> tempListStorage = new LinkedList<>();
            for (List<Integer> list : lists) {
                for (int i = 1; i < 26; i++) {
                    List<Integer> tempList = Lists.newArrayList(list);
                    if (!tempList.contains(i)) {
                        tempList.add(i);
                        tempListStorage.add(tempList);
                    }

                }
                list.add(0);
            }
            lists.addAll(tempListStorage);
        }
    }

    public static List<Integer> createMustHaveListTopDown(List<Integer> mustHaveList, ArrayList<Report> reportList) {

        List<Integer> shortestMustHaveList = null;
        System.out.println("Testing:" + mustHaveList.toString());

        for (Integer i : mustHaveList) {

            ArrayList<Report> reducedReportList = createDeletedReportlistCopy(i, reportList);
            if (isDistinguishable(reducedReportList)) {
                System.out.println("Is Distinguishable:" + mustHaveList.toString() + " without " + i);

                List<Integer> newTestList = new LinkedList<>();
                for (int j = 0; j < mustHaveList.size(); j++) {
                    if (mustHaveList.get(j) != i) {
                        newTestList.add(mustHaveList.get(j));
                    }
                }
                if (Arrays.equals(mustHaveList.toArray(), newTestList.toArray())) {
                    continue;
                }
                List<Integer> shortest = createMustHaveListTopDown(newTestList, reducedReportList);
                if (shortestMustHaveList == null) {
                    shortestMustHaveList = shortest;
                } else if (shortestMustHaveList.size() > shortest.size()) {
                    shortestMustHaveList = shortest;
                }
            }
        }
        return shortestMustHaveList;
    }

    private static ArrayList<Report> createDeletedReportlistCopy(Integer i, ArrayList<Report> toCopyList) {
        ArrayList<Report> newReportList = new ArrayList<>();
        for (Report r : toCopyList) {
            Report copy = new Report(r);
            for (CsvReport csv : copy.getVulnerabilityList()) {
                if (csv.getResponseMap().size() > i) {
                    csv.getResponseMap().set(i, null);
                }
            }
            newReportList.add(copy);
        }
        return newReportList;
    }

    public static boolean isDistinguishable(ArrayList<Report> tempReportList) {
        //System.out.println("Starting response distinguisable test: " + tempReportList.size());
        for (Report report : tempReportList) {

            for (CsvReport csv : report.getVulnerabilityList()) {
                if (!csv.isShaky() && !csv.isScanError() && csv.isVulnerable()) {
                    // System.out.println(csv.getResponseMap());
                    Set<String> hashSet = new HashSet<>();
                    for (String s : csv.getResponseMap()) {
                        if (s == null) {
                            continue;
                        }
                        hashSet.add(s.split("paddingVector")[0]);
                    }
                    if (hashSet.size() == 1 || hashSet.isEmpty()) {
                        return false;
                    } else {
                        //System.out.println("Is distinguishable");
                    }
                }
            }
        }
        return true;
    }

    private static List<Integer> testForSolution(List<List<Integer>> toTestLists) {
        for (List<Integer> list : toTestLists) {
            ArrayList<Report> toTestReportList = new ArrayList<>();
            for (Report report : reportList) {
                Report tempReport = new Report(report);
                for (CsvReport csv : tempReport.getVulnerabilityList()) {
                    for (int i = 0; i < csv.getResponseMap().size(); i++) {
                        if (!list.contains(i)) {
                            csv.getResponseMap().set(i, null);
                        }
                    }
                }
                toTestReportList.add(tempReport);
            }
            if (isDistinguishable(toTestReportList)) {
                return list;
            }
        }
        return null;
    }

    private static void updateCipherSuiteStats(Document d) {
        String id = d.getString("_id");
        String host = d.getString("targetIp");
        IScanTask task = pp.getScanTask(id);
        Collection<IScanResult> results = task.getResults();
        for (IScanResult result : results) {
            List<ITuple<String, Object>> contents = result.getContents();
            for (ITuple<String, Object> tuple : contents) {
                if (tuple.getFirst().equals("host")) {
                    host = tuple.getSecond().toString();
                }
                if (tuple.getFirst().equals("ciphers")) {
                    ScanResult ciphers = (ScanResult) tuple.getSecond();
                    List<ITuple<String, Object>> scanResultList = ciphers.getContents();
                    for (ITuple<String, Object> sth : scanResultList) {
                        if (sth.getFirst().equals("cipherSuites")) {
                            //Now we have all the cipherSuites lists
                            processCipherSuiteList((List<String>) sth.getSecond());
                        }
                    }
                }
            }
        }
    }

    private static void processCipherSuiteList(List<String> cipherSuiteList) {
        Set<String> suiteSet = new HashSet<>();
        for (String s : cipherSuiteList) {
            suiteSet.add(s);
        }
        for (String s : suiteSet) {
            CipherSuite suite = CipherSuite.valueOf(s);
            if (suite != null) {
                if (allSuiteMap.containsKey(suite)) {
                    MutableInt get = allSuiteMap.get(suite);
                    get.addValue(1);
                } else {
                    allSuiteMap.put(suite, new MutableInt(1));
                }
            }
        }
    }
}
