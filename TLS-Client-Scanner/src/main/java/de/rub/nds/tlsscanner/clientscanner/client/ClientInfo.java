package de.rub.nds.tlsscanner.clientscanner.client;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlSeeAlso;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.DockerLibAdapter.DockerClientInfo;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.BaseCommandAdapter.CommandClientInfo;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.BaseCommandAdapter.CommandInfo;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ProxiedLocalCommandExecutor.ProxiedLocalSystemInfo;

@XmlSeeAlso({
        CommandClientInfo.class,
        CommandInfo.class,
        ProxiedLocalSystemInfo.class,
        DockerClientInfo.class,
})
public abstract class ClientInfo implements Serializable {
    public abstract String toShortString();
}
