/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.targetlist;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipInputStream;

import de.rub.nds.tlscrawler.constant.CruxListNumber;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Target list provider that downloads the most recent tranco list (https://tranco-list.eu/) and
 * extracts the top x hosts from it.
 */
public class CruxListProvider implements ITargetListProvider {

    private static final String SOURCE = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz";
    private static final String ZIP_FILENAME = "current.csv.gz";
    private static final String FILENAME = "current.csv";
    private static final Logger LOGGER = LogManager.getLogger();

    private final int number;

    public CruxListProvider(CruxListNumber cruxListNumber) {
        this.number = cruxListNumber.getNumber();
    }

    @Override
    public List<String> getTargetList() {
        List<String> targetList;
        try {
            LOGGER.info("Downloading current Crux list...");
            ReadableByteChannel readableByteChannel =
                    Channels.newChannel(new URL(SOURCE).openStream());
            FileOutputStream fileOutputStream = new FileOutputStream(ZIP_FILENAME);
            fileOutputStream.getChannel().transferFrom(readableByteChannel, 0, Long.MAX_VALUE);
            fileOutputStream.close();
        } catch (IOException e) {
            LOGGER.error("Could not download the current Crux list with error ", e);
        }
        LOGGER.info("Unzipping current Crux list...");
        try (GZIPInputStream zis = new GZIPInputStream(new FileInputStream(ZIP_FILENAME))) {
            File newFile = new File(FILENAME);
            // write file content
            FileOutputStream fos = new FileOutputStream(newFile);
            int len;
            byte[] buffer = new byte[1024];
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
        } catch (IOException e) {
            LOGGER.error("Could not unzip the current Crux list with error ", e);
        }
        LOGGER.info("Reading first {} host from current Crux list...", number);
        // currently hosts are in order. e.g. top 1000 hosts come first but that does not have to be the case
        // therefore, we parse every line until we hit the specified number of hosts
        try (Stream<String> lines = Files.lines(Paths.get(FILENAME))) {
            // filter to all correctly ranked hosts, ignore RAW http hosts and map to final domain
            targetList = lines.filter(line -> line.contains("https://")).filter(line -> Integer.parseInt(line.split("\\,")[1]) <= number).map(line -> line.split("\\,")[0].split(":\\/\\/")[1]).collect(Collectors.toList());
        } catch (IOException ex) {
            throw new RuntimeException("Could not load " + FILENAME, ex);
        }
        LOGGER.info("Deleting files...");
        try {
            Files.delete(Path.of(ZIP_FILENAME));
        } catch (IOException e) {
            LOGGER.error("Could not delete " + ZIP_FILENAME + ": ", e);
        }
        try {
            Files.delete(Path.of(FILENAME));
        } catch (IOException e) {
            LOGGER.error("Could not delete " + FILENAME + ": ", e);
        }
        return targetList;
    }
}
