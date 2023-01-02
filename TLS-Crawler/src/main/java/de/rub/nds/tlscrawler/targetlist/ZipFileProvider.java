/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.targetlist;

import java.io.*;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ZipFileProvider implements ITargetListProvider {

    protected static final Logger LOGGER = LogManager.getLogger();
    protected final int number;
    private final String sourceUrl;
    private final String zipFilename;
    private final String outputFile;
    private final String listName;

    protected ZipFileProvider(
            int number, String sourceUrl, String zipFilename, String outputFile, String listName) {
        this.number = number;
        this.sourceUrl = sourceUrl;
        this.zipFilename = zipFilename;
        this.outputFile = outputFile;
        this.listName = listName;
    }

    public List<String> getTargetList() {
        List<String> targetList;
        try {
            ReadableByteChannel readableByteChannel =
                    Channels.newChannel(new URL(sourceUrl).openStream());
            FileOutputStream fileOutputStream = new FileOutputStream(zipFilename);
            fileOutputStream.getChannel().transferFrom(readableByteChannel, 0, Long.MAX_VALUE);
            fileOutputStream.close();
        } catch (IOException e) {
            LOGGER.error("Could not download the current " + listName + " list with error ", e);
        }
        LOGGER.info("Unzipping current " + listName + " list...");
        try (InflaterInputStream zis = getZipInputStream(zipFilename)) {
            if (zis instanceof ZipInputStream) {
                ((ZipInputStream) zis).getNextEntry();
            }
            File newFile = new File(outputFile);
            // write file content
            FileOutputStream fos = new FileOutputStream(newFile);
            int len;
            byte[] buffer = new byte[1024];
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
        } catch (IOException e) {
            LOGGER.error("Could not unzip the current " + listName + " list with error ", e);
        }
        LOGGER.info("Reading first {} hosts from current " + listName + " list...", number);
        // currently hosts are in order. e.g. top 1000 hosts come first but that does not have to be
        // the case. Therefore, we parse every line until we hit the specified number of hosts
        try (Stream<String> lines = Files.lines(Paths.get(outputFile))) {
            targetList = getTargetListFromLines(lines);
        } catch (IOException ex) {
            throw new RuntimeException("Could not load " + outputFile, ex);
        }
        LOGGER.info("Deleting files...");
        try {
            Files.delete(Path.of(zipFilename));
        } catch (IOException e) {
            LOGGER.error("Could not delete " + zipFilename + ": ", e);
        }
        try {
            Files.delete(Path.of(outputFile));
        } catch (IOException e) {
            LOGGER.error("Could not delete " + outputFile + ": ", e);
        }
        return targetList;
    }

    private InflaterInputStream getZipInputStream(String filename) throws IOException {
        if (filename.contains(".gz")) {
            return new GZIPInputStream(new FileInputStream(filename));
        } else {
            return new ZipInputStream(new FileInputStream(filename));
        }
    }

    protected abstract List<String> getTargetListFromLines(Stream<String> lines);
}
