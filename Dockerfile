FROM maven:3.6.1-jdk-8 AS build-image
WORKDIR /build
RUN git clone https://github.com/RUB-NDS/TLS-Scanner.git --recurse-submodules

WORKDIR /build/TLS-Scanner
RUN mvn clean install -DskipTests=true

#############
FROM openjdk:8-alpine

COPY --from=build-image /build/TLS-Scanner/apps /apps

WORKDIR /apps
ENTRYPOINT ["java", "-jar", "TLS-Server-Scanner.jar"]

