/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.Option;
import com.google.devtools.common.options.OptionsBase;
import com.google.devtools.common.options.OptionsParser;
import com.google.devtools.common.options.OptionsParsingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.UUID;

/**
 * Command Line Options class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class CLOptions extends OptionsBase {
    private static Logger LOG = LoggerFactory.getLogger(CLOptions.class);

    private static OptionsParser parser = OptionsParser.newOptionsParser(CLOptions.class);

    @Option(
            name = "help",
            abbrev = 'h',
            help = "Prints usage info.",
            defaultValue = "false"
    )
    public boolean help;

    @Option(
            name = "isMaster",
            abbrev = 'm',
            help = "Runs TLS-Crawler in Master or Slave mode.",
            defaultValue = "false"
    )
    public boolean isMaster;

    @Option(
            name = "instanceId",
            abbrev = 'i',
            help = "The ID of this TLS-Crawler instance.",
            defaultValue = ""
    )
    public String instanceId;

    @Option(
            name = "mongoDbConnectionString",
            abbrev = 'o',
            help = "Connection string of the MongoDB instance this crawler saves to.",
            defaultValue = ""
    )
    public String mongoDbConnectionString;

    @Option(
            name = "redisConnectionString",
            abbrev = 'r',
            help = "Connection string of the Redis instance this crawler uses to coordinate.",
            defaultValue = ""
    )
    public String redisConnectionString;

    @Option(
            name = "masterOnly",
            abbrev = 'y',
            help = "Spawns a master-only instance, isMaster is implicit.",
            defaultValue = "false"
    )
    public boolean masterOnly;

    @Option(
            name = "inMemoryOrchestration",
            abbrev = 'x',
            help = "Uses an in-memory orchestration provider. Can not be combined with masterOnly.",
            defaultValue = "false"
    )
    public boolean inMemoryOrchestration;

    @Option(
            name = "testMode",
            abbrev = 't',
            help = "Starts TLS Crawler in test mode, using in-memory orchestration and persistence.",
            defaultValue = "false"
    )
    public boolean testMode;

    /**
     * Implements command line argument parsing.
     *
     * @param args The argument array.
     * @return An object containing sane arguments.
     * @throws OptionsParsingException
     */
    public static CLOptions parseOptions(String[] args) throws OptionsParsingException {
        CLOptions result;

        LOG.trace("parseOptions()");

        parser.parse(args);
        result = parser.getOptions(CLOptions.class);

        if (result != null && result.instanceId.equals("")) {
            result.instanceId = UUID.randomUUID().toString();
        }

        if (result != null && result.masterOnly && !result.isMaster) {
            LOG.warn("Overridden 'isMaster' to true due to 'masterOnly'.");
            result.isMaster = true;
        }

        if (result != null && result.testMode && !result.isMaster) {
            LOG.warn("Overridden 'isMaster' to true due to 'testMode' option.");
            result.isMaster = true;
        }

        if (result != null && result.testMode && !result.inMemoryOrchestration) {
            LOG.warn("Overridden 'inMemoryOrchestration' to true due to 'testMode' option.");
            result.inMemoryOrchestration = true;
        }

        return result;
    }

    public static String getHelpString() {
        return parser.describeOptions(Collections.<String, String>emptyMap(), OptionsParser.HelpVerbosity.LONG);
    }
}
