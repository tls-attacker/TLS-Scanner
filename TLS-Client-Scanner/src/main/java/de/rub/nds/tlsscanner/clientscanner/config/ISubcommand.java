package de.rub.nds.tlsscanner.clientscanner.config;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public interface ISubcommand {
    void addToJCommander(JCommander jc);

    void setParsed(JCommander jc) throws ParameterException;

    void applyDelegate(Config config);
}
