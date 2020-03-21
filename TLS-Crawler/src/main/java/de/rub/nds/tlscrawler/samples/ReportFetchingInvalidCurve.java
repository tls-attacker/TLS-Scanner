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
public class ReportFetchingInvalidCurve {

    private static ArrayList<InvalidCurveReport> reportList = new ArrayList<>();

    public static void main(String... args) {

        // SETUP
        String mongoHost = "localhost";//"192.168.129.133";
        int mongoPort = 1337;
        String mongoUser = "janis";
        String mongoAuthSource = "admin";
        String mongoPass = "myStrongPass123!";
        String mongoWorkspace = "TLSC-dev-invalCAlexaConf4";
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
        
        MongoCollection<Document> collection = database.getCollection("invalCurveScans");
        FindIterable<Document> find = collection.find(new BsonDocument("results.tls_scan.supportsSslTls", new BsonBoolean(true)));
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
                    if (tuple.getFirst().equals("invalidCurve")) {
                        ScanResult paddingOracleResults = (ScanResult) tuple.getSecond();
                        List<ITuple<String, Object>> scanResultList = paddingOracleResults.getContents();
                        for (ITuple<String, Object> sth : scanResultList) {
                            if (sth.getFirst().equals("invalidCurveResults")) {
                                processScanResultsList(host, ((List) sth.getSecond()));
                            }
                        }
                    }
                }
            }
        }
        System.out.println("Creating graph");
        createGraph(reportList, "full");
    }
    private static MongoPersistenceProvider pp;

    private static void processScanResultsList(String host, List<ScanResult> scanResultList) {
        InvalidCurveReport report = new InvalidCurveReport(host);
        boolean isFaulty = false;
        boolean foundNotValidated = false;
        boolean foundOtherThanXvuln = false; // filter hosts that only omitted validation for X-curves

        for (ScanResult result : scanResultList) {
            List<ITuple<String, Object>> resultContents = result.getContents();
            
            ParameterSetResult psResult = new ParameterSetResult();
            List<String> cipherSuites = new ArrayList<>();
            boolean showsNotValidated = false;
            boolean showsKeyReuse = false;
            boolean showsVulnerability = false;
            String pointFormat = "";
            String namedGroup = "";
            String protocolVersion = "";
            boolean twistAttack = false;
            boolean attackInRenegotiation = false;
            
            for (ITuple<String, Object> tempTuple : resultContents) {
                
                if(tempTuple.getFirst().equals("cipherSuites")) {
                    cipherSuites = (List<String>) tempTuple.getSecond();
                }
                else if (tempTuple.getFirst().equals("pointFormat")) {
                    pointFormat = ((String) (tempTuple.getSecond()));
                }
                else if(tempTuple.getFirst().equals("namedGroup")) {
                    namedGroup = ((String) (tempTuple.getSecond()));
                }
                else if(tempTuple.getFirst().equals("protocolVersion")) {
                    protocolVersion = ((String) (tempTuple.getSecond()));
                }
                else if(tempTuple.getFirst().equals("twistAttack")) {
                    twistAttack = ((boolean) (tempTuple.getSecond()));
                }
                else if(tempTuple.getFirst().equals("attackInRenegotiation")) {
                    attackInRenegotiation = ((boolean) (tempTuple.getSecond()));
                }
                else if(tempTuple.getFirst().equals("fingerprintSecretPairs")) {
                    //find all unique reactions to invalid curve vector
                    List<ScanResult> fps = ((List) tempTuple.getSecond());
                    for(ScanResult fpResult : fps) {
                        List<ITuple<String, Object>> fpContents = fpResult.getContents();
                        for(ITuple<String, Object> fpTuple : fpContents) {
                            if(fpTuple.getFirst().equals("responseFingerprint")) {
                                String responseFingerprint = ((String) (fpTuple.getSecond()));
                                if(!psResult.containsFingerprint(responseFingerprint)) {
                                    psResult.getUniqueFingerprints().add(responseFingerprint);
                                }
                            }
                        }
                    }
                }
                else if(tempTuple.getFirst().equals("showsPointsAreNotValidated")) {
                    String validationTestResult = (String) (tempTuple.getSecond());
                    if(validationTestResult.equals("TRUE")){
                        showsNotValidated = true;
                        foundNotValidated = true;
                    } else if(validationTestResult.equals("ERROR_DURING_TEST")) {
                        showsNotValidated = false;
                        isFaulty = true;
                    } else {
                        showsNotValidated = false;
                    }
                }
                else if(tempTuple.getFirst().equals("chosenGroupReusesKey")) {
                    if(((String) (tempTuple.getSecond())).equals("TRUE")){
                        showsKeyReuse = true;
                    } else {
                        showsKeyReuse = false;
                    }
                }
                else if(tempTuple.getFirst().equals("showsVulnerability")) {
                    if(((String) (tempTuple.getSecond())).equals("TRUE")){
                        showsVulnerability = true;
                    } else {
                        showsVulnerability = false;
                    }
                }            
            }
            
            //construct parameter set string
            String parameter = ">";
            if(!namedGroup.contains("X") && showsNotValidated) {
                foundOtherThanXvuln = true; // don't filter this one out
            }
            parameter = protocolVersion + ">" + namedGroup + ">"
                + (attackInRenegotiation ? "Renegotiation>" : "") + pointFormat + parameter
                + (twistAttack ? ">CurveTwist" : "");
            
            //add to report of host
            psResult.setShowsKeyReuse(showsKeyReuse);
            psResult.setShowsNotValidated(showsNotValidated);
            psResult.setShowsVulnerability(showsVulnerability);
            report.getParameterSetMap().put(parameter, psResult);

        }

        if(!isFaulty && report.getParameterSetMap().keySet().size() > 0 && foundNotValidated && foundOtherThanXvuln){
            reportList.add(report);
        }
    }

    public static void createGraph(List<InvalidCurveReport> tempReportList, String name) {
        UndirectedGraph<String, DefaultEdge> graph = new SimpleGraph<>(DefaultEdge.class);
        UndirectedGraph<String, DefaultEdge> invertedGraph = new SimpleGraph<>(DefaultEdge.class);

        for (InvalidCurveReport report : tempReportList) {
            //Create node
            graph.addVertex("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));
            invertedGraph.addVertex("Host_" + report.getHost().replace("-", "_dash_").replace(":443", "").replace(".", "_dot_"));

        }
        System.out.println("Creating Graph");

        int i = 0;

        for (InvalidCurveReport report : tempReportList) {
            i++;
            for (InvalidCurveReport otherReport : tempReportList) {
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
            Logger.getLogger(ReportFetchingInvalidCurve.class
                    .getName()).log(Level.SEVERE, null, ex);
        }

        System.out.println("Done writing Graph");
    }


}
