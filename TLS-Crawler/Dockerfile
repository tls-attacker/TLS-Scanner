FROM maven:3.6.0-jdk-11-slim AS build
ARG GIT_USR
ARG GIT_PWD
ARG MODVAR_BRANCH=master
ARG ASN1_BRANCH=master
ARG X509_BRANCH=master
ARG ATTACKER_BRANCH=master
ARG SCANNER_BRANCH=master

WORKDIR /

RUN apt-get update
RUN apt-get install git -y

# ModifiableVariable
RUN git clone https://$GIT_USR:$GIT_PWD@github.com/tls-attacker/ModifiableVariable.git
WORKDIR /ModifiableVariable
RUN git checkout $MODVAR_BRANCH
RUN mvn clean install -DskipTests
WORKDIR /

# ASN1-Tool
RUN git clone https://$GIT_USR:$GIT_PWD@github.com/tls-attacker/ASN.1-Tool-Development.git
WORKDIR /ASN.1-Tool-Development
RUN git checkout $ASN1_BRANCH
RUN mvn clean install -DskipTests
WORKDIR /

# X509-Attacker
RUN git clone https://$GIT_USR:$GIT_PWD@github.com/tls-attacker/X509-Attacker-Development.git
WORKDIR /X509-Attacker-Development
RUN git checkout $X509_BRANCH
RUN mvn clean install -DskipTests
WORKDIR /

# TLS-Attacker
RUN git clone https://$GIT_USR:$GIT_PWD@github.com/tls-attacker/TLS-Attacker-Development.git
WORKDIR /TLS-Attacker-Development
RUN git checkout $ATTACKER_BRANCH
RUN mvn clean install -DskipTests
WORKDIR /

# TLS-Scanner
RUN git clone https://$GIT_USR:$GIT_PWD@github.com/tls-attacker/TLS-Scanner-Development.git
WORKDIR /TLS-Scanner-Development
RUN git checkout $SCANNER_BRANCH
RUN mvn clean install -DskipTests
WORKDIR /

# TLS-Crawler built from this repository
COPY ./ /TLS-Crawler/
RUN ls TLS-Crawler
WORKDIR /TLS-Crawler
RUN git checkout upb-crawler-updated
RUN mvn clean install -DskipTests

FROM openjdk:11-jre-slim
COPY --from=build /root/.m2/repository/ /root/.m2/repository/
# dirty copying of dependencies into /lib folder
RUN for i in `find /root/.m2/repository/ -iname '*.jar'`; do cp $i /lib; done

# copy dependencies
COPY --from=build /TLS-Crawler/target/lib /lib
COPY --from=build /TLS-Crawler/target/*.jar TLS-Crawler.jar

ENTRYPOINT ["java", "-jar", "TLS-Crawler.jar"]