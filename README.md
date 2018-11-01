# Likensing client

This is a small library with zero dependencies which could be included to parse licenses created by [Likensing Server](https://github.com/fkrone/likensing-server). It is just a little fun project. Feel free to fork and improve it.

# Getting started
Generate a public private key pair via the Likensing Server.

Supply the base64 encoded public key to the ```LicenseChecker``` class via ```LicenseChecker::initLicenseChecker```. After initializing the checker you can get the instance of the checker via ```LicenseChecker::getChecker```.
To add a license or provide a newer license, pass the base64 encoded license to the checker via ```LicenseChecker::importLicense```.
To check if a scope has a feature licensed, call ```LicenseChecker::isLicensed``` with the scope uid and the feature to check. The method will return true if the feature is licensed, false otherwise.

# License

Likensing Client is licensed under the MIT License.