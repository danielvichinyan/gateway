FROM maven:3.6.3-openjdk-14 AS build
COPY src /src
COPY pom.xml /
RUN mvn clean package -DskipTests

FROM openjdk:14
VOLUME /tmp
ARG JAR_FILE=target/*.jar
COPY --from=build ${JAR_FILE} app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]