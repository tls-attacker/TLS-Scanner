/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.config;

import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;

import de.rub.nds.tlsattacker.core.config.Config;

public abstract class BaseSubcommandHolder<T extends Subcommand> implements Subcommand {
    protected List<T> subcommands = new ArrayList<>();
    protected T selectedSubcommand;

    private void addToJCommander(JCommander jc, String name) {
        jc.addCommand(name, this);
        JCommander subCommander = jc.getCommands().get(name);
        for (Subcommand subcommand : subcommands) {
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
            throw new ParameterException(
                "Trying to add command " + getClass().getName() + " without specifying its names in @Parameters");
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
        if (commandJc == null) {
            throw new ParameterException("Did not find JCommander for name " + commandName);
        }
        List<Object> cmdObjs = commandJc.getObjects();
        T cmd = (T) cmdObjs.get(0);
        selectedSubcommand = cmd;
        cmd.setParsed(commandJc);
    }

    @Override
    public void applyDelegate(Config config) {
        selectedSubcommand.applyDelegate(config);
        applyDelegateInternal(config);
    }

    protected abstract void applyDelegateInternal(Config config);

}
