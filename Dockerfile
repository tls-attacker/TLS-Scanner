FROM maven:3.6.1-jdk-11 AS build-image
WORKDIR /build
ADD ./ /build/TLS-Scanner

WORKDIR /build/TLS-Scanner
RUN mvn clean install -DskipTests=true

#############
FROM openjdk:11

COPY --from=build-image /build/TLS-Scanner/apps /apps

WORKDIR /apps
ENTRYPOINT ["java", "-jar", "TLS-Server-Scanner.jar"]

