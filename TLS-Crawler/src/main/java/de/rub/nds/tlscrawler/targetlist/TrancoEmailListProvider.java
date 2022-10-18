/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.targetlist;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Target list provider that downloads the most recent tranco list (https://tranco-list.eu/) and extracts the top x
 * hosts from it and then searches for mail servers in the dns mx records of the hosts and returns these as targets.
 */
public class TrancoEmailListProvider implements ITargetListProvider {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ITargetListProvider trancoList;

    public TrancoEmailListProvider(ITargetListProvider trancoList) {
        this.trancoList = trancoList;
    }

    @Override
    public List<String> getTargetList() {
        List<String> dnsList = new ArrayList<>();
        try {
            InitialDirContext iDirC = new InitialDirContext();
            List<String> hostList = new ArrayList<>(this.trancoList.getTargetList());
            LOGGER.info("Fetching MX Hosts");
            for (String hold : hostList) {
                String hostname = hold.substring(hold.lastIndexOf(',') + 1);
                try {
                    Attributes attributes = iDirC.getAttributes("dns:/" + hostname, new String[] { "MX" });
                    Attribute attributeMX = attributes.get("MX");

                    if (attributeMX != null) {
                        for (int i = 0; i < attributeMX.size(); i++) {
                            String getMX = attributeMX.get(i).toString();
                            dnsList.add(getMX.substring(getMX.lastIndexOf(' ') + 1));
                        }
                    }
                } catch (NamingException e) {
                    LOGGER.error("No MX record found for host: {} with error {}", hostname, e);
                }
            }
        } catch (NamingException e) {
            LOGGER.error(e);
        }
        return dnsList.stream().distinct().collect(Collectors.toList());
    }
}
