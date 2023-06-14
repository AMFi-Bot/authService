FROM eclipse-temurin:17-jdk-alpine as build                                                                                                                                                           
WORKDIR /app                                                                                                                                                                                          
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src

RUN --mount=type=cache,target=/root/.m2 ./mvnw package -DskipTests
RUN cp target/*.jar /app.jar

EXPOSE 8080

FROM eclipse-temurin:17-jdk-alpine as development
COPY --from=build /app.jar /app.jar
ENTRYPOINT ["java","-Dspring-boot.run.jvmArguments='-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000'","-Dspring.profiles.active=dev","-jar","/app.jar"]

FROM eclipse-temurin:17-jdk-alpine as production
COPY --from=build /app.jar /app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-Dspring.profiles.active=prod","-jar","/app.jar"]
