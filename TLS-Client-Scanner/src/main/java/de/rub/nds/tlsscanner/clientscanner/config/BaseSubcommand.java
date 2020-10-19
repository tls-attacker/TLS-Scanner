/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config;

import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;

public abstract class BaseSubcommand implements ISubcommand {
    protected List<ISubcommand> subcommands = new ArrayList<>();
    protected ISubcommand selectedSubcommand;

    private void addToJCommander(JCommander jc, String name) {
        jc.addCommand(name, this);
        JCommander subCommander = jc.getCommands().get(name);
        for (ISubcommand subcommand : subcommands) {
            subcommand.addToJCommander(subCommander);
        }
    }

    @Override
    public void addToJCommander(JCommander jc) {
        Parameters p = getClass().getAnnotation(Parameters.class);
        if (p != null && p.commandNames().length > 0) {
            for (String commandName : p.commandNames()) {
                addToJCommander(jc, commandName);
            }
        } else {
            throw new ParameterException("Trying to add command " + getClass().getName()
                    + " without specifying its names in @Parameters");
        }
    }

    @Override
    public void setParsed(JCommander jc) throws ParameterException {
        if (subcommands.isEmpty()) {
            return;
        }
        // find selected subCommand
        String commandName = jc.getParsedCommand();
        JCommander commandJc = jc.getCommands().get(commandName);
        List<Object> cmdObjs = commandJc.getObjects();
        ISubcommand cmd = (ISubcommand) cmdObjs.get(0);
        selectedSubcommand = cmd;
        cmd.setParsed(commandJc);
    }

}
