FROM openjdk:8-slim-stretch
RUN apt-get update && apt-get upgrade -y && apt-get -y install git maven 
RUN git clone https://github.com/RUB-NDS/TLS-Attacker.git
RUN git clone https://github.com/RUB-NDS/TLS-Scanner.git
WORKDIR /TLS-Attacker/
RUN mvn clean install -DskipTests=true
RUN git clone https://github.com/RUB-NDS/TLS-Scanner.git
WORKDIR /TLS-Scanner/
RUN mvn clean install -DskipTests=true
WORKDIR /TLS-Scanner/apps/
ENTRYPOINT ["java" ,"-jar","TLS-Scanner.jar"]
