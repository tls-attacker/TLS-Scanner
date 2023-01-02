/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.targetlist;

import de.rub.nds.tlscrawler.constant.CruxListNumber;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Target list provider that downloads the most recent crux list (<a
 * href="https://github.com/zakird/crux-top-lists">...</a>) and extracts the top x hosts from it.
 */
public class CruxListProvider extends ZipFileProvider {

    private static final String SOURCE =
            "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz";
    private static final String ZIP_FILENAME = "current.csv.gz";
    private static final String FILENAME = "current.csv";

    public CruxListProvider(CruxListNumber cruxListNumber) {
        super(cruxListNumber.getNumber(), SOURCE, ZIP_FILENAME, FILENAME, "Crux");
    }

    @Override
    protected List<String> getTargetListFromLines(Stream<String> lines) {
        // Line format is <protocol>://<domain>, <crux rank>
        // filter...
        return
        // ... ignore all none http
        lines.filter(line -> line.contains("https://"))
                // ... limit to names with correct crux rank
                .filter(line -> Integer.parseInt(line.split(",")[1]) <= number)
                // ... ignore crux rank and protocol
                .map(line -> line.split(",")[0].split("://")[1])
                .collect(Collectors.toList());
    }
}
