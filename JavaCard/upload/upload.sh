echo 'uninstall previously loaded applet'
java -jar gp.jar -uninstall SimpleApplet.cap

echo 'load new version'
java -jar gp.jar -install SimpleApplet.cap -verbose -d

echo 'list available applets'
java -jar gp.jar -l
