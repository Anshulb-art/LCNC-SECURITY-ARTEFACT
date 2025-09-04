# SAST — SonarQube Evidence & How-To

Screens show Dockerized SonarQube setup, token creation, and analyses for Coffee, Purchase, and Task.

## Key takeaways
- All three apps analyzed successfully in SonarQube.
- Some warnings (cipher mode/padding) for Task — review & mitigate.
- Use sonar.java.binaries for Java artifacts; exclude generated/minified code to focus on app logic.

## What to look for
- Figure 1–2: SonarQube setup & token.
- Figures 3–5: per-app sonar-project.properties files.
- Figures 6–11: scan results (pass/warnings).
