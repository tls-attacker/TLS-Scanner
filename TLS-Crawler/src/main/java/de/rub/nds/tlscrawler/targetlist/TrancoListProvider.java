/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.targetlist;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Target list provider that downloads the most recent tranco list (<a
 * href="https://tranco-list.eu/">...</a>) and extracts the top x hosts from it.
 */
public class TrancoListProvider extends ZipFileProvider {

    private static final String SOURCE = "https://tranco-list.eu/top-1m.csv.zip";
    private static final String ZIP_FILENAME = "tranco-1m.csv.zip";
    private static final String FILENAME = "tranco-1m.csv";

    public TrancoListProvider(int number) {
        super(number, SOURCE, ZIP_FILENAME, FILENAME, "Tranco");
    }

    @Override
    protected List<String> getTargetListFromLines(Stream<String> lines) {
        return lines.limit(this.number).collect(Collectors.toList());
    }
}
