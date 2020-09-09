FROM maven:3.6.1-jdk-8 AS build-image
WORKDIR /build
RUN git clone https://github.com/RUB-NDS/ASN.1-Tool.git && cd ASN.1-Tool && mvn clean install && cd ..
RUN git clone https://github.com/RUB-NDS/X509-Attacker.git && cd X509-Attacker && mvn clean install && cd ..
RUN git clone https://github.com/RUB-NDS/TLS-Scanner.git --recurse-submodules

RUN git clone https://github.com/RUB-NDS/TLS-Attacker.git && \
    TLS_ATTACKER_VERSION=$(cat TLS-Scanner/pom.xml | grep -A 1 "<artifactId>TLS-Core</artifactId>" | grep -o -E "[0-9.]+") && \
    cd TLS-Attacker && \
    git checkout "tags/$TLS_ATTACKER_VERSION" -b "$TLS_ATTACKER_VERSION" && \
    mvn clean install -DskipTests=true

WORKDIR /build/TLS-Scanner
RUN mvn clean install -DskipTests=true

#############
FROM openjdk:8-alpine

COPY --from=build-image /build/TLS-Scanner/apps /apps

WORKDIR /apps
ENTRYPOINT ["java", "-jar", "TLS-Scanner.jar"]

