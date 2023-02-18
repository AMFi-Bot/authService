FROM eclipse-temurin:17-jdk-alpine

# Build a project
WORKDIR /app
COPY ./src ./src
COPY ./gradle ./gradle
COPY ./build.gradle.kts .
COPY ./settings.gradle.kts .
COPY ./gradlew .

RUN ./gradlew build

#Copy production executable jar file to destination dir
RUN mkdir /dist
# Gradle generates two .jars in dist folder, base and plain. Copy only one, base, file
RUN cp ./build/libs/$(ls ./build/libs/ | grep -v -e="*plain*") /dist/app.jar

# Run the server
ENTRYPOINT ["java","-jar","/dist/app.jar","--server.port=8080"]
EXPOSE 8080
