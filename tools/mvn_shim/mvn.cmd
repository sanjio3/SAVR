@echo off
REM Maven shim for Windows cmd - launch java + classworlds directly, bypassing broken mvn launcher.
REM Used by CodeQL autobuild (codeql database create --language=java -> mvn clean package) so A1
REM injection detection works on Java projects (improvement checklist P0#1).
REM Keep this file ASCII-only and avoid parentheses in comments: full-width parens in REM lines
REM break cmd parsing and make if/set statements fail.
setlocal
set "JAVA=java"
set "MH=C:\apache-maven-3.9.11"
set "BOOT=%MH%\boot\plexus-classworlds-2.9.0.jar"
set "CONF=%MH%\bin\m2.conf"
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set "JAVA=%JAVA_HOME%\bin\java.exe"
if defined MAVEN_HOME if exist "%MAVEN_HOME%\boot\plexus-classworlds-2.9.0.jar" set "MH=%MAVEN_HOME%"
if not exist "%JAVA%" echo mvn_shim: JAVA not found: %JAVA% 1>&2 && exit /b 1
if not exist "%BOOT%" echo mvn_shim: classworlds boot jar not found: %BOOT% 1>&2 && exit /b 1
"%JAVA%" -Xmx192m -Xms32m -XX:+UseSerialGC -XX:MaxMetaspaceSize=128m -cp "%BOOT%" -Dclassworlds.conf="%CONF%" -Dmaven.home="%MH%" -Dmaven.multiModuleProjectDirectory="%CD%" -Dspotless.check.skip=true -Dspotless.apply.skip=true -Dlicense.skip=true -Dmaven.gitcommitid.skip=true -Dspring-boot.repackage.skip=true org.codehaus.plexus.classworlds.launcher.Launcher %*
