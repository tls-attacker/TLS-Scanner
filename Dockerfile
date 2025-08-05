FROM maven:3.9.9-eclipse-temurin-21-jammy AS build-image
WORKDIR /build
RUN git clone https://github.com/RUB-NDS/TLS-Scanner.git

WORKDIR /build/TLS-Scanner
RUN git submodule update --init --recursive
RUN mvn clean package

#############
FROM eclipse-temurin:21

COPY --from=build-image /build/TLS-Scanner/apps /apps

WORKDIR /apps
ENTRYPOINT ["java", "-jar", "TLS-Server-Scanner.jar"]
