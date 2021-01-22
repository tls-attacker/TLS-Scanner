FROM maven:3.6.3-jdk-8-slim
WORKDIR /
COPY . /TLS-Crawler
# build TLS-Crawler
RUN cd /TLS-Crawler && mvn clean package -DskipTests


FROM openjdk:8-jre-slim
WORKDIR /
COPY --from=0 /TLS-Crawler/target/*.jar /TLS-Crawler.jar
COPY --from=0 /TLS-Crawler/target/lib /lib
ENTRYPOINT ["java", "-jar", "TLS-Crawler.jar"]
