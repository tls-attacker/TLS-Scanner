/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.OptionsParsingException;
import de.rub.nds.tlscrawler.options.MasterSlaveOptions;
import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.scans.ScanFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * Slave instance main class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class Slave {
    private static Logger LOG = LoggerFactory.getLogger(Slave.class);

    public static void main(String[] args) {
        MasterSlaveOptions options;

        try {
            options = MasterSlaveOptions.parseOptions(args);
        } catch (OptionsParsingException ex) {
            LOG.error("Command Line Options could not be parsed.");
            options = null;
        }

        if (options == null || options.help) {
            System.out.println("Could not parse Command Line Options. Try again:");
            System.out.println(MasterSlaveOptions.getHelpString());
            System.exit(0);
        }

        Collection<IScan> scans = ScanFactory.getInstance().getBuiltInScans();
    }
}
