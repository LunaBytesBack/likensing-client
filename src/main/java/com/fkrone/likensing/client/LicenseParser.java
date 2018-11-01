package com.fkrone.likensing.client;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Parses and verifies licenses.
 */
class LicenseParser {

    /**
     * The public key to check the license's signature against.
     */
    private PublicKey publicKey;

    /**
     * Creates a new instance of the parser.
     *
     * @param publicKey the public key to verify the signature against
     */
    LicenseParser(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Parses a provided license into a {@link LicenseData} and verifies the
     * signature's validity.
     *
     * @param license the license to parse
     * @return the parsed and verified license wrapped in a {@link LicenseData}
     * @throws NoSuchAlgorithmException if the signature algorithm is not available
     * @throws InvalidKeyException      if the public key to verify the license is invalid
     * @throws TransformerException     if parsing the license fails
     * @throws SignatureException       if a forged license is found
     * @throws IOException              if parsing the license fails due to internal handling
     */
    LicenseData parseLicense(String license)
            throws NoSuchAlgorithmException, InvalidKeyException, TransformerException, SignatureException,
                   IOException {
        Document parsedLicense = parseLicenseXML(license);
        Element rootElement = parsedLicense.getDocumentElement();
        Node licensedProperties = querySingleNode(rootElement, "licensedProperties");
        String signKeyAsString = queryTextNode(rootElement, "signKey");
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(nodeToBytes(licensedProperties));
            if (!signature.verify(decodeBase64(signKeyAsString))) {
                throw new SecurityException("Sign key does not match license.");
            }
        } catch (SignatureException e) {
            throw new SignatureException("Forged license found!", e);
        }

        String scopeId = queryTextNode(licensedProperties, "scopeUid");
        long validUntilTimestamp = queryLongNode(licensedProperties, "validUntil");
        LocalDate validUntil = Instant.ofEpochMilli(validUntilTimestamp).atZone(ZoneId.systemDefault()).toLocalDate();

        Node licensedFeaturesNode = querySingleNode(licensedProperties, "licensedFeatures");

        Set<String> licensedFeatures = new HashSet<>();
        queryTextNodeListContent(licensedFeaturesNode, "feature").forEach(licensedFeatures::add);

        return new LicenseData(scopeId, licensedFeatures, validUntil);
    }

    /**
     * Queries a single sub element from the given node.
     *
     * @param node       the node to query a sub element of
     * @param elementTag the tag of the element to query
     * @return the queried sub element
     */
    private Node querySingleNode(Node node, String elementTag) {
        assertNodeElementNode(node);
        NodeList nodeList = ((Element) node).getElementsByTagName(elementTag);
        if (nodeList.getLength() != 1) {
            throw new IllegalArgumentException("Cannot parse XML tag "
                                               + elementTag
                                               + " as it has "
                                               + nodeList.getLength()
                                               + " appearances instead of expected 1.");
        }
        return nodeList.item(0);
    }

    /**
     * Queries the string content of a sub element for the given node.
     *
     * @param node       the node to query the string content of a sub element of
     * @param elementTag the tag of the element to query
     * @return the string content of the queried sub element
     */
    private String queryTextNode(Node node, String elementTag) {
        Node textNode = querySingleNode(node, elementTag);
        return queryStringFromNode(textNode);
    }

    /**
     * Queries the content of a sub element as long for the given node.
     *
     * @param node       the node to query the content as long of a sub element of
     * @param elementTag the tag of the element to query
     * @return the content of the queried sub element as long or 0 if the content
     * cannot be parsed
     */
    private long queryLongNode(Node node, String elementTag) {
        String nodeText = queryTextNode(node, elementTag);
        try {
            return Long.parseLong(nodeText);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    /**
     * Queries a list of nodes from the given node with the given
     * element tag and converts their content to parsed strings.
     *
     * @param node       the node to query the list of elements of
     * @param elementTag the tag of the elements to query
     * @return a list containing the string content of the matching
     * sub elements from the node
     */
    private List<String> queryTextNodeListContent(Node node, String elementTag) {
        assertNodeElementNode(node);
        List<String> nodeContents = new ArrayList<>();

        NodeList nodeList = ((Element) node).getElementsByTagName(elementTag);
        for (int i = 0; i < nodeList.getLength(); i++) {
            nodeContents.add(queryStringFromNode(nodeList.item(i)));
        }
        return nodeContents;
    }

    private void assertNodeElementNode(Node node) {
        if (node.getNodeType() != Node.ELEMENT_NODE) {
            throw new IllegalArgumentException("XML node " + node.getNodeName() + " is not an expected element node.");
        }
    }

    /**
     * Transforms a node to its byte representation.
     * <p>
     * This is used to transform the licensed properties to
     * the representation it was signed with.
     *
     * @param node the node to transform
     * @return a byte array representing the supplied node
     * @throws TransformerException if the transformation process fails
     * @throws IOException          if the internal handling of the node fails
     */
    private byte[] nodeToBytes(Node node) throws TransformerException, IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(byteArrayOutputStream))) {
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            Transformer transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(new DOMSource(node), new StreamResult(writer));
        }
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * Converts and trims the content of a node.
     *
     * @param nodeToQuery the node to retrieve the text content of
     * @return the text content of the node
     */
    private String queryStringFromNode(Node nodeToQuery) {
        if (nodeToQuery == null) {
            throw new IllegalArgumentException("Expected node not found.");
        }
        String textContent = nodeToQuery.getTextContent();
        if (textContent == null) {
            return "";
        }
        return textContent.trim();
    }

    /**
     * Parses the given license string into an {@link Document} element
     * which could be further queried.
     *
     * @param license the license to parse
     * @return the license parsed in a Document which could be
     * further processed.
     * @throws IOException if internal handling of the license fails
     */
    private Document parseLicenseXML(String license) throws IOException {
        byte[] decodedLicense = decodeBase64(license);
        try (ByteArrayInputStream licenseStream = new ByteArrayInputStream(decodedLicense)) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(licenseStream);
        } catch (ParserConfigurationException | SAXException | CharConversionException e) {
            throw new IllegalArgumentException("Failed to parse provided license.", e);
        }
    }

    private byte[] decodeBase64(String textToDecode) {
        return Base64.getDecoder().decode(textToDecode);
    }
}
