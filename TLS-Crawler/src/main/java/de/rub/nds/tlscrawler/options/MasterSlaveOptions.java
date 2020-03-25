/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.options;

import com.google.devtools.common.options.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.UUID;

/**
 * Command Line Options for the slave main method.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class MasterSlaveOptions extends OptionsBase {
    private static Logger LOG = LoggerFactory.getLogger(MasterSlaveOptions.class);

    private static OptionsParser parser = OptionsParser.newOptionsParser(MasterSlaveOptions.class);

    @Option(
            name = "help",
            abbrev = 'h',
            help = "Prints usage info.",
            defaultValue = "false"
    )
    public boolean help;

    @Option(
            name = "instanceId",
            abbrev = 'i',
            help = "The ID of this TLS-Crawler instance.",
            defaultValue = ""
    )
    public String instanceId;

    @Option(
            name = "mongoDbHost",
            abbrev = 'o',
            help = "Host of the MongoDB instance this crawler saves to.",
            defaultValue = "localhost"
    )
    public String mongoDbHost;

    @Option(
            name = "mongoDbPort",
            abbrev = 'p',
            help = "Port of the MongoDB instance this crawler saves to.",
            defaultValue = "27017"
    )
    public int mongoDbPort;

    @Option(
            name = "mongoDbUser",
            help = "The username to be used to authenticate with the MongoDB instance.",
            defaultValue = ""
    )
    public String mongoDbUser;

    @Option(
            name = "mongoDbPass",
            help = "The passwort to be used to authenticate with MongoDB.",
            defaultValue = ""
    )
    public String mongoDbPass;

    @Option(
            name = "mongoDbAuthSource",
            help = "The DB within the MongoDB instance, in which the user:pass is defined.",
            defaultValue = ""
    )
    public String mongoDbAuthSource;

    @Option(
            name = "redisHost",
            abbrev = 'r',
            help = "Host of the Redis instance this crawler uses to coordinate.",
            defaultValue = "localhost"
    )
    public String redisHost;

    @Option(
            name = "redisPort",
            abbrev = 'q',
            help = "Port of the Redis instance this crawler uses to coordinate.",
            defaultValue = "6379"
    )
    public int redisPort;

    @Option(
            name = "redisPass",
            abbrev = 'a',
            help = "Password of the Redis instance this crawler uses to coordinate.",
            defaultValue = ""
    )
    public String redisPass;

    @Option(
            name = "workspace",
            abbrev = 'w',
            help = "Instances in the same workspace share the same databases.",
            defaultValue = ""
    )
    public String workspace;

    private static String DEFAULT_WORKSPACE = "default";

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
    public static MasterSlaveOptions parseOptions(String[] args) throws OptionsParsingException {
        MasterSlaveOptions result;

        result = Options.parse(MasterSlaveOptions.class, args).getOptions();

        MasterSlaveOptions.checkResult(result);

        return result;
    }

    protected static void checkResult(MasterSlaveOptions result) {
        if (result != null && result.workspace.equals("")) {
            LOG.warn("No workspace name set. This might cause trouble when using " +
                    "more than a single instance of TLS-Crawler.");
            result.workspace = DEFAULT_WORKSPACE;
        }

        if (result != null && result.instanceId.equals("")) {
            result.instanceId = UUID.randomUUID().toString();
        }

        boolean saneMongoLogin = saneMongoLogin(result.mongoDbUser, result.mongoDbPass, result.mongoDbAuthSource);
        if (result != null && !saneMongoLogin) {
            LOG.warn("Did not specify a full set of mongo credentials (none is fine for unsecured instances).");
        }
    }

    private static boolean saneMongoLogin(String user, String pass, String authSource) {
        if (user.equals("") && pass.equals("") && authSource.equals("")) {
            return true;
        } else if (!user.equals("") && !pass.equals("") && !authSource.equals("")) {
            return true;
        } else {
            return false;
        }
    }
}
