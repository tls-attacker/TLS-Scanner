/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.constants;

import java.util.Set;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "result")
@XmlAccessorType(XmlAccessType.FIELD)
public class SetResult<T> implements TestResult{

	private String name="SetResult";
	private final Set<T> set;
	
	public SetResult(Set<T> set){
		this.set = set;
	}
	
	public SetResult(Set<T> set, String name){
		this.set = set;
		this.name = name;
	}
	
	public Set<T> getSet() {
		return this.set;
	}
	
	@Override
	public String name() {
		return this.name;
	}
}
