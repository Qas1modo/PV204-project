echo 'uninstall previously loaded applet'
java -jar gp.jar -uninstall SecretStorage.cap

echo 'load new version'
java -jar gp.jar -install SecretStorage.cap -verbose -d

echo 'list available applets'
java -jar gp.jar -l
