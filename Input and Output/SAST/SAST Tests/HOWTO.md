# How to re-run SAST (Windows + Docker)

## Start SonarQube
- Install Docker Desktop (WSL2).
- Run: docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community
- Open http://localhost:9000 → create project + token.

## Per-app setup
- Put sonar-project.properties in repo root (as shown in your figures).
- Set sonar.java.binaries=deployment/run/bin when applicable (Mendix).
- Exclude generated paths: deployment/**, 	hemesource/**, 
ode_modules/**, **/*.min.js, **/*.map.

## Run scans
- Set env: $env:SONAR_HOST_URL='http://host.docker.internal:9000' & $env:SONAR_TOKEN='squ_...'.
- Use sonarsource/sonar-scanner-cli in Docker with your code mounted.
- For Task, increase Node heap: -Dsonar.javascript.node.maxspace=6144.

## Troubleshooting
- 401 → check token/URL.
- No Java classes → set sonar.java.binaries.
- Slow JS analysis → increase Node heap or add exclusions.
