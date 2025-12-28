# Confiance auth-service

## Overview
Part of the Confiance Financial Platform microservices architecture.

## Port
- **Default Port**: 8081

## Technology Stack
- Java 17
- Spring Boot 3.2.0
- Maven

## Building

```bash
mvn clean package
```

## Running Locally

```bash
mvn spring-boot:run
```

## Docker

```bash
docker build -t confiance/auth-service:latest .
docker run -p 8081:8081 confiance/auth-service:latest
```

## Environment Variables

See `application.yml` for required configuration.

## Documentation

- [Main Documentation](https://github.com/confiance-platform/confiance-platform)
- [API Documentation](../docs/API.md)

## License
Proprietary - Confiance Financial Platform
