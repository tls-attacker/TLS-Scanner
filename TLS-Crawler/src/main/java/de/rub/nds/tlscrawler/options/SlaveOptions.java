/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.options;

import com.google.devtools.common.options.Option;
import com.google.devtools.common.options.Options;
import com.google.devtools.common.options.OptionsParser;
import com.google.devtools.common.options.OptionsParsingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

/**
 * Options for the dedicated Slave class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class SlaveOptions extends MasterSlaveOptions {
    private static Logger LOG = LoggerFactory.getLogger(SlaveOptions.class);

    private static OptionsParser parser = OptionsParser.newOptionsParser(SlaveOptions.class);

    @Option(
            name = "numberOfThreads",
            help = "Number of worker threads the crawler slave should use.",
            defaultValue = "500"
    )
    public int numberOfThreads;

    /**
     * @return Command Line Argument description.
     */
    public static String getHelpString() {
        return parser.describeOptions(Collections.<String, String>emptyMap(), OptionsParser.HelpVerbosity.LONG);
    }

    /**
     * Implements command line argument parsing.
     *
     * @param args The argument array.
     * @return An object containing sane arguments.
     * @throws OptionsParsingException
     */
    public static SlaveOptions parseOptions(String[] args) throws OptionsParsingException {
        SlaveOptions result;

        result = Options.parse(SlaveOptions.class, args).getOptions();

        MasterSlaveOptions.checkResult(result);

        return result;
    }
}
