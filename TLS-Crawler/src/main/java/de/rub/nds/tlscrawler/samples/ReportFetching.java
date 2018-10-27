/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.samples;

import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.wrapper.MutableInt;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.persistence.MongoPersistenceProvider;
import de.rub.nds.tlscrawler.utility.ITuple;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

    public static void main(String... args) {

        // SETUP
        String mongoHost = "cloud.nds.rub.de";
        int mongoPort = 42133;
        String mongoUser = "janis";
        String mongoAuthSource = "admin";
        String mongoPass = "myStrongPass123!";
        String mongoWorkspace = "TLSC-paddingOracle-15";

        // EXEC
        ServerAddress addr = new ServerAddress(mongoHost, mongoPort);
        MongoCredential cred = MongoCredential.createCredential(
                mongoUser,
                mongoAuthSource,
                mongoPass.toCharArray());
        MongoPersistenceProvider pp = new MongoPersistenceProvider(addr, cred);
        pp.init(mongoWorkspace);
        try {
            BufferedReader reader = new BufferedReader(new FileReader(new File("vulnIds")));
            String line;
            while ((line = reader.readLine()) != null) {
                IScanTask task = pp.getScanTask(line);
                Collection<IScanResult> results = task.getResults();
                for (IScanResult result : results) {
                    List<ITuple<String, Object>> contents = result.getContents();
                    String host = null;
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
        } catch (Exception E) {
            E.printStackTrace();
        }
        System.out.println("----ErrorTypes----");
        for (EqualityError error : EqualityError.values()) {
            if (errorMap.containsKey(error)) {
                System.out.println("" + error.name() + ": " + errorMap.get(error).getValue());
            }
        }

        System.out.println("----Vuln Suites----");
        for (CipherSuite suite : CipherSuite.values()) {
            if (suiteMap.containsKey(suite)) {
                System.out.println("" + suite.name() + ": " + suiteMap.get(suite).getValue());
            }
        }

        System.out.println("----Vuln Version----");
        for (ProtocolVersion version : ProtocolVersion.values()) {
            if (versionMap.containsKey(version)) {
                System.out.println("" + version.name() + ": " + versionMap.get(version).getValue());
            }
        }
    }

    private static void processScanResultsList(String host, List<ScanResult> scanResultList) {
        Set<String> vulnerableSuffix = new HashSet<>();
        Set<String> notVulnSuffix = new HashSet<>();

        for (ScanResult result : scanResultList) {
            List<ITuple<String, Object>> resultContents = result.getContents();
            EqualityError equailityError = null;
            CipherSuite suite = null;
            ProtocolVersion version = null;
            Boolean vulnerable = null;
            Boolean shaky = null;

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

        }
        for (String suffix : vulnerableSuffix) {
            if (notVulnSuffix.contains(suffix)) {
                System.out.println(host + " - " + suffix);
            }
        }
    }
}
