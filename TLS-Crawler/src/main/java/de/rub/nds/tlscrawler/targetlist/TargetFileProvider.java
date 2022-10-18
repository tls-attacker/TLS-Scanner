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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TargetFileProvider implements ITargetListProvider {

    private static final Logger LOGGER = LogManager.getLogger();

    private String filename;

    public TargetFileProvider(String filename) {
        this.filename = filename;
    }

    @Override
    public List<String> getTargetList() {
        LOGGER.info("Reading hostName list");
        List<String> targetList;
        try (Stream<String> lines = Files.lines(Paths.get(filename))) {
            targetList = lines.collect(Collectors.toList());
        } catch (IOException ex) {
            throw new RuntimeException("Could not load " + filename, ex);
        }
        LOGGER.info("Read " + targetList.size() + " hosts");
        return targetList;
    }
}
