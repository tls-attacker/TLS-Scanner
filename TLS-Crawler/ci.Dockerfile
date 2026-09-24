FROM openjdk:11-jre
WORKDIR /
COPY ./apps/*.jar /TLS-Crawler.jar
COPY ./apps/lib/*.jar /lib/
ENTRYPOINT ["java", "-jar", "TLS-Crawler.jar"]
