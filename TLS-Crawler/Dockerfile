FROM maven:3.8.6-openjdk-11-slim AS build

ARG MODVAR_BRANCH=main
ARG ASN1_BRANCH=main
ARG X509_BRANCH=main
ARG ATTACKER_BRANCH=main
ARG SCANNER_BRANCH=main
ARG CRAWLER_CORE_BRANCH=main

WORKDIR /

RUN apt-get update \
    && apt-get install git -y \
    && apt clean
COPY docker/install-dependencies.sh /install-dependencies.sh
RUN --mount=type=secret,id=m2settings,dst=/root/.m2/settings.xml \
    --mount=type=secret,id=credentials_provider,dst=/credentials_provider.sh \
    bash /credentials_provider.sh run-with-credentials /install-dependencies.sh

# TLS-Crawler built from current state of the repository
COPY . /TLS-Crawler/
WORKDIR /TLS-Crawler
RUN --mount=type=secret,id=m2settings,dst=/root/.m2/settings.xml \
    mvn clean install -DskipTests -Dspotless.apply.skip

FROM openjdk:21-jre-slim
COPY --from=build /root/.m2/repository/ /root/.m2/repository/
# dirty copying of dependencies into /lib folder
RUN for f in `find /root/.m2/repository/ -iname '*.jar'`; do cp "$f" /lib; done

# copy dependencies
COPY --from=build /TLS-Crawler/apps/lib /lib
COPY --from=build /TLS-Crawler/target/*.jar TLS-Crawler.jar

ENTRYPOINT ["java", "-jar", "TLS-Crawler.jar"]
