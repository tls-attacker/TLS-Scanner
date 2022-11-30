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
import java.util.zip.ZipInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Target list provider that downloads the most recent tranco list (https://tranco-list.eu/) and
 * extracts the top x hosts from it.
 */
public class TrancoListProvider implements ITargetListProvider {

    private static final String SOURCE = "https://tranco-list.eu/top-1m.csv.zip";
    private static final String ZIP_FILENAME = "tranco-1m.csv.zip";
    private static final String FILENAME = "tranco-1m.csv";
    private static final Logger LOGGER = LogManager.getLogger();

    private final int amount;

    public TrancoListProvider(int amount) {
        this.amount = amount;
    }

    @Override
    public List<String> getTargetList() {
        List<String> targetList;
        try {
            LOGGER.info("Downloading current Tranco list...");
            ReadableByteChannel readableByteChannel =
                    Channels.newChannel(new URL(SOURCE).openStream());
            FileOutputStream fileOutputStream = new FileOutputStream(ZIP_FILENAME);
            fileOutputStream.getChannel().transferFrom(readableByteChannel, 0, Long.MAX_VALUE);
            fileOutputStream.close();
        } catch (IOException e) {
            LOGGER.error("Could not download the current Tranco list with error ", e);
        }
        LOGGER.info("Unzipping current Tranco list...");
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(ZIP_FILENAME))) {
            zis.getNextEntry();
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
            LOGGER.error("Could not unzip the current Tranco list with error ", e);
        }
        LOGGER.info("Reading first {} host from current Tranco list...", amount);
        try (Stream<String> lines = Files.lines(Paths.get(FILENAME))) {
            targetList = lines.limit(this.amount).collect(Collectors.toList());
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
