FROM maven:3.6.1-jdk-11 AS build-image
WORKDIR /build
RUN git clone https://github.com/RUB-NDS/ModifiableVariable.git 
RUN git clone https://github.com/RUB-NDS/ASN.1-Tool.git
RUN git clone https://github.com/RUB-NDS/X509-Attacker.git
RUN git clone https://github.com/RUB-NDS/TLS-Attacker.git
RUN git clone https://github.com/RUB-NDS/TLS-Scanner.git --recurse-submodules
WORKDIR /build/ModifiableVariable
RUN git checkout tags/3.5.0
RUN mvn clean install -DskipTests=true
WORKDIR /build/ASN.1-Tool
RUN mvn clean install -DskipTests=true
WORKDIR /build/X509-Attacker
RUN mvn clean install -DskipTests=true

WORKDIR /build/TLS-Attacker
RUN mvn clean install -DskipTests=true

WORKDIR /build/TLS-Scanner
RUN mvn clean install -DskipTests=true

#############
FROM openjdk:11

COPY --from=build-image /build/TLS-Scanner/apps /apps

WORKDIR /apps
ENTRYPOINT ["java", "-jar", "TLS-Server-Scanner.jar"]

