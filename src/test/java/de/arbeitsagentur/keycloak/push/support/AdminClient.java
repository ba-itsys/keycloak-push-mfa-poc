package de.arbeitsagentur.keycloak.push.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public final class AdminClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final URI baseUri;
    private final HttpClient http =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private String accessToken;

    public AdminClient(URI baseUri) {
        this.baseUri = baseUri;
    }

    public JsonNode fetchPushCredential(String userId) throws Exception {
        JsonNode items = readCredentials(userId);
        for (JsonNode item : items) {
            if ("push-mfa".equals(item.path("type").asText())) {
                String credentialData = item.path("credentialData").asText();
                return MAPPER.readTree(credentialData);
            }
        }
        throw new IllegalStateException("Push credential not found for user " + userId);
    }

    public void resetUserState(String username) throws Exception {
        String userId = findUserId(username);
        if (userId == null || userId.isBlank()) {
            throw new IllegalStateException("User not found: " + username);
        }
        deletePushCredentials(userId);
        logoutUser(userId);
    }

    private void deletePushCredentials(String userId) throws Exception {
        JsonNode credentials = readCredentials(userId);
        for (JsonNode item : credentials) {
            if (!"push-mfa".equals(item.path("type").asText())) {
                continue;
            }
            String credentialId = item.path("id").asText(null);
            if (credentialId == null || credentialId.isBlank()) {
                continue;
            }
            URI deleteUri = baseUri.resolve("/admin/realms/push-mfa/users/" + userId + "/credentials/" + credentialId);
            HttpRequest deleteRequest = HttpRequest.newBuilder(deleteUri)
                    .header("Authorization", "Bearer " + accessToken)
                    .DELETE()
                    .build();
            HttpResponse<String> deleteResponse = http.send(deleteRequest, HttpResponse.BodyHandlers.ofString());
            assertEquals(204, deleteResponse.statusCode(), () -> "Credential delete failed: " + deleteResponse.body());
        }
    }

    private void logoutUser(String userId) throws Exception {
        URI logoutUri = baseUri.resolve("/admin/realms/push-mfa/users/" + userId + "/logout");
        HttpRequest request = HttpRequest.newBuilder(logoutUri)
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(204, response.statusCode(), () -> "Logout failed: " + response.body());
    }

    private JsonNode readCredentials(String userId) throws Exception {
        ensureAccessToken();
        URI credentialsUri = baseUri.resolve("/admin/realms/push-mfa/users/" + userId + "/credentials");
        HttpRequest request = HttpRequest.newBuilder(credentialsUri)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Credential fetch failed: " + response.body());
        JsonNode items = MAPPER.readTree(response.body());
        if (!items.isArray()) {
            throw new IllegalStateException("Unexpected credential response: " + response.body());
        }
        return items;
    }

    private String findUserId(String username) throws Exception {
        ensureAccessToken();
        URI usersUri = baseUri.resolve("/admin/realms/push-mfa/users?username=" + urlEncode(username));
        HttpRequest request = HttpRequest.newBuilder(usersUri)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "User lookup failed: " + response.body());
        JsonNode users = MAPPER.readTree(response.body());
        if (users.isArray() && users.size() > 0) {
            return users.get(0).path("id").asText(null);
        }
        return null;
    }

    private void ensureAccessToken() throws Exception {
        if (accessToken != null && !accessToken.isBlank()) {
            return;
        }
        URI tokenUri = baseUri.resolve("/realms/master/protocol/openid-connect/token");
        String body = "grant_type=password&client_id=admin-cli&username=admin&password=admin";
        HttpRequest request = HttpRequest.newBuilder(tokenUri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Admin token request failed: " + response.body());
        JsonNode json = MAPPER.readTree(response.body());
        accessToken = json.path("access_token").asText();
        assertNotNull(accessToken);
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
