FROM maven:3.6.1-jdk-8
RUN git clone https://github.com/RUB-NDS/TLS-Attacker.git
RUN git clone https://github.com/RUB-NDS/TLS-Scanner.git --recurse-submodules
WORKDIR /TLS-Attacker/
RUN mvn clean install -DskipTests=true
WORKDIR /TLS-Scanner/
RUN mvn clean install -DskipTests=true
WORKDIR /TLS-Scanner/apps/
ENTRYPOINT ["java" ,"-jar","TLS-Scanner.jar"]
