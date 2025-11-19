package de.arbeitsagentur.keycloak.push.support;

import java.net.URI;
import org.jsoup.nodes.Document;

public record HtmlPage(URI uri, Document document) {}
