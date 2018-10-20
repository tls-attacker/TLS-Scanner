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
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.persistence.MongoPersistenceProvider;

/**
 * Sample script fetching a database record and parsing it into a
 * TLS Scanner Site Report Object.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ReportFetching {

    public static void main(String... args) {

        // SETUP
        String mongoHost = "cloud.nds.rub.de";
        int mongoPort = 42133;
        String mongoUser = "janis";
        String mongoAuthSource = "admin";
        String mongoPass = "myStrongPass123!";
        String mongoWorkspace = "TLSC-paddingOracle-8";

        String idToFind = "7e5f0cd7-7924-470f-aadb-1a55e94625f4";

        // EXEC
        ServerAddress addr = new ServerAddress(mongoHost, mongoPort);
        MongoCredential cred = MongoCredential.createCredential(
                mongoUser,
                mongoAuthSource,
                mongoPass.toCharArray());
        MongoPersistenceProvider pp = new MongoPersistenceProvider(addr, cred);
        pp.init(mongoWorkspace);
        IScanTask task = pp.getScanTask(idToFind);

        // OUTPUT
        if (task != null) {
            System.out.println(task.toString());
        } else {
            System.out.println("Couldn't find task with id " + idToFind);
        }
    }
}
