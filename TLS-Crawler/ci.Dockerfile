FROM openjdk:11-jre
WORKDIR /
COPY ./apps/*.jar /TLS-Crawler.jar
COPY ./apps/lib/*.jar /lib/
COPY ./elastic-apm-agent-*.jar /elastic-apm-agent.jar
ENTRYPOINT ["java", "-javaagent:elastic-apm-agent.jar", "-jar", "TLS-Crawler.jar"]
