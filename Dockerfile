FROM eclipse-temurin:17-jdk-jammy as base

WORKDIR /app

COPY gradle/ gradle
COPY settings.gradle.kts build.gradle.kts gradlew ./
RUN ./gradlew dependencies --no-daemon
COPY src/ src



FROM base as development
CMD ["./gradlew", "bootRun", "--no-daemon","-Dspring-boot.run.jvmArguments='-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000'"]



FROM base as build
RUN ./gradlew bootJar --no-daemon



FROM eclipse-temurin:17-jre-jammy as production
EXPOSE 8080

COPY --from=build /app/build/libs/ /compiledJars

#Copy production executable jar file to destination dir
RUN mkdir /dist
# Gradle generates two .jars in dist folder, base and plain. Copy only one, base, file
RUN cp /compiledJars/$(echo $(ls /compiledJars/ | grep -v -e="*plain*") | awk '{print $1}') /dist/app.jar
CMD ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/dist/app.jar"]