package com.fkrone.likensing.client;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.SignatureException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LicenseParsingTest {

    private static LicenseChecker licenseChecker;

    @BeforeClass
    public static void setupChecker() throws Exception {
        LicenseChecker.initLicenseChecker(
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi74pE2wrMJLRESst3v3iwSYbbrtZNJbbGR+aAdlNeaM3ZW5KaVPhj8Z5HVboiFnzDT4yu8O9c6HX5AiKbd3OxkZxZGpXkv1xnQimKLcfdI2o1+aamBdzr37wWC/8/WJvew/EuAG7x9HTzpO9XrMh64LIP2Mk6QQkrRdgFdiyq5CZDDh0zHAW2Cz55l1NGUb/U9X5nKLyL9Fon49lbixqULsAkKMKWlQMLWiGFwOAI1U/RQ19QD1aMG4YTL/wrqPvkUkpy8E1wEe57WMuLFFMffj5dnfK3MLw+mtRFqQlJh6TYohUIbVdqvCtBWM8MLa0bfZnMhyOnmcIn8WRrE+IWwIDAQAB");
        licenseChecker = LicenseChecker.getChecker();
    }

    @Test
    public void parsingValidLicense() throws Exception {
        licenseChecker.importLicense(
                "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48bGljZW5zZT4KPGxpY2Vuc2VkUHJvcGVydGllcz4KPGxpY2Vuc2VkRmVhdHVyZXM+CjxmZWF0dXJlPnRlc3QxPC9mZWF0dXJlPgo8ZmVhdHVyZT50ZXN0MzwvZmVhdHVyZT4KPC9saWNlbnNlZEZlYXR1cmVzPgo8dmFsaWRVbnRpbD40MTAyMzU0ODAwMDAwPC92YWxpZFVudGlsPgo8c2NvcGVVaWQ+dGVzdHNjb3BlPC9zY29wZVVpZD4KPC9saWNlbnNlZFByb3BlcnRpZXM+CjxzaWduS2V5PlNRWnkrNGxQdXBET05ubWFDNmRRUUJyYnJoU01WTmtwMHBMYitEUUcwZmN2d0gzYzgyM3JZcThXRGswWldSV3ZDMWozOGJNOGRGNmQ4YUphaGFCbDNqcUNJRndyU2E4STR5aTJ6ME1jUXo5VzVvRm9vaWtmNXlzTG5iT0xZTTdwQXNEL2YzSVlBYXdxdXgrYUNjeGF5ZEhjK2t4MWROMThIbURJY2sydTV4MHU4dFhwejJ0bG94Z1haaUVqUVpTeFB0NUdSbGMrK1BMQ3F5Z3d0REMzNkI5NUFVYkJoLzZuOFh2LzNhZis2YTAvMGMrYmhaQmpBNjMwSGszZTJLVFU4UkJBL1VXTzdZbTdLdzI5MnFKOHVhU2JrVGh5akp6dFFrYlM0eVJwbWlmdUVGYVdETVBVZkdpRXFrY1BRM05LQXJCejF5cm5WYXJnY1RVNS84VHpaZz09PC9zaWduS2V5Pgo8L2xpY2Vuc2U+Cg==");

        assertTrue(licenseChecker.hasLicense("testscope"));
        assertFalse(licenseChecker.isLicensed("testscope", "test2"));
        assertTrue(licenseChecker.isLicensed("testscope", "test1"));
        assertTrue(licenseChecker.isLicensed("testscope", "test3"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void parsingEmptyLicense() throws Exception {
        licenseChecker.importLicense("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void parsingUnencodedString() throws Exception {
        licenseChecker.importLicense("Invalid");
    }

    @Test(expected = SignatureException.class)
    public void parseInvalidSignedLicense() throws Exception {
        licenseChecker.importLicense(
                "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48bGljZW5zZT4KPGxpY2Vuc2VkUHJvcGVydGllcz4KPGxpY2Vuc2VkRmVhdHVyZXM+CjxmZWF0dXJlPnRlc3QxPC9mZWF0dXJlPgo8ZmVhdHVyZT50ZXN0MzwvZmVhdHVyZT4KPC9saWNlbnNlZEZlYXR1cmVzPgo8dmFsaWRVbnRpbD40MTAyMzU0ODAwMDAwPC92YWxpZFVudGlsPgo8c2NvcGVVaWQ+dGVzdHNjb3BlPC9zY29wZVVpZD4KPC9saWNlbnNlZFByb3BlcnRpZXM+CjxzaWduS2V5PkludmFsaWQ8L3NpZ25LZXk+CjwvbGljZW5zZT4=");
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseMalformedLicense() throws Exception {
        licenseChecker.importLicense(
                "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48bGljZW5zZT4KPGxpY2Vuc2VkUHJvcGVydGllcz4KPGxpY2Vuc2VkRmVhdHVyZXM+CjxmZWF0dXJlPnRlc3QxPC9mZWF0dXJlPgo8ZmVhdHVyZT50ZXN0MzwvZmVhdHVyZT4KPHZhbGlkVW50aWw+NDEwMjM1NDgwMDAwMDwvdmFsaWRVbnRpbD4KPHNjb3BlVWlkPnRlc3RzY29wZTwvc2NvcGVVaWQ+CjwvbGljZW5zZWRQcm9wZXJ0aWVzPgo8c2lnbktleT5TUVp5KzRsUHVwRE9Obm1hQzZkUVFCcmJyaFNNVk5rcDBwTGIrRFFHMGZjdndIM2M4MjNyWXE4V0RrMFpXUld2QzFqMzhiTThkRjZkOGFKYWhhQmwzanFDSUZ3clNhOEk0eWkyejBNY1F6OVc1b0Zvb2lrZjV5c0xuYk9MWU03cEFzRC9mM0lZQWF3cXV4K2FDY3hheWRIYytreDFkTjE4SG1ESWNrMnU1eDB1OHRYcHoydGxveGdYWmlFalFaU3hQdDVHUmxjKytQTENxeWd3dERDMzZCOTVBVWJCaC82bjhYdi8zYWYrNmEwLzBjK2JoWkJqQTYzMEhrM2UyS1RVOFJCQS9VV083WW03S3cyOTJxSjh1YVNia1RoeWpKenRRa2JTNHlScG1pZnVFRmFXRE1QVWZHaUVxa2NQUTNOS0FyQnoxeXJuVmFyZ2NUVTUvOFR6Wmc9PTwvc2lnbktleT4KPC9saWNlbnNlPgo=");
    }
}
