FROM maven:3.9.9-eclipse-temurin-21-jammy AS build-image
WORKDIR /build
COPY . .
RUN mvn clean package

FROM eclipse-temurin:21

COPY --from=build-image /build/apps /apps

WORKDIR /apps
ENTRYPOINT ["java", "-jar", "TLS-Server-Scanner.jar"]
