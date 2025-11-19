package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.push.support.AdminClient;
import de.arbeitsagentur.keycloak.push.support.BrowserSession;
import de.arbeitsagentur.keycloak.push.support.DeviceClient;
import de.arbeitsagentur.keycloak.push.support.DeviceKeyType;
import de.arbeitsagentur.keycloak.push.support.DeviceSigningKey;
import de.arbeitsagentur.keycloak.push.support.DeviceState;
import de.arbeitsagentur.keycloak.push.support.HtmlPage;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PushMfaIntegrationIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path EXTENSION_JAR = locateProviderJar();
    private static final Path REALM_FILE =
            Paths.get("config", "push-mfa-realm.json").toAbsolutePath();
    private static final String TEST_USERNAME = "test";

    @Container
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.4.5")
            .withExposedPorts(8080)
            .withCopyFileToContainer(
                    MountableFile.forHostPath(EXTENSION_JAR), "/opt/keycloak/providers/keycloak-push-mfa.jar")
            .withCopyFileToContainer(
                    MountableFile.forHostPath(REALM_FILE), "/opt/keycloak/data/import/push-mfa-realm.json")
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .withCommand(
                    "start-dev --hostname=localhost --hostname-strict=false --http-enabled=true --import-realm --features=dpop")
            .waitingFor(Wait.forHttp("/realms/master").forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(3));

    private URI baseUri;
    private AdminClient adminClient;

    @BeforeAll
    void setup() {
        baseUri = URI.create(String.format("http://%s:%d/", KEYCLOAK.getHost(), KEYCLOAK.getMappedPort(8080)));
        adminClient = new AdminClient(baseUri);
    }

    @Test
    void deviceEnrollsAndApprovesLogin() throws Exception {
        try {
            DeviceClient deviceClient = enrollDevice();
            completeLoginFlow(deviceClient);
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    @Test
    void ecdsaDeviceEnrollsAndApprovesLogin() throws Exception {
        try {
            DeviceClient deviceClient = enrollDevice(DeviceKeyType.ECDSA);
            completeLoginFlow(deviceClient);
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    @Test
    void deviceRotatesKeyAndAuthenticates() throws Exception {
        try {
            DeviceClient deviceClient = enrollDevice();
            DeviceSigningKey rotatedKey = DeviceSigningKey.generateRsa();
            String status = deviceClient.rotateDeviceKey(rotatedKey);
            assertEquals("rotated", status);

            JsonNode credentialData =
                    adminClient.fetchPushCredential(deviceClient.state().userId());
            JsonNode storedKey =
                    MAPPER.readTree(credentialData.path("publicKeyJwk").asText());
            assertEquals(MAPPER.readTree(rotatedKey.publicJwk().toJSONString()), storedKey);

            completeLoginFlow(deviceClient);
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    @Test
    void deviceUpdatesPushProvider() throws Exception {
        try {
            DeviceClient deviceClient = enrollDevice();
            String newProviderId = "integration-provider-" + UUID.randomUUID();
            String newProviderType = "log-updated";
            String status = deviceClient.updatePushProvider(newProviderId, newProviderType);
            assertEquals("updated", status);

            JsonNode credentialData =
                    adminClient.fetchPushCredential(deviceClient.state().userId());
            assertEquals(newProviderId, credentialData.path("pushProviderId").asText());
            assertEquals(
                    newProviderType, credentialData.path("pushProviderType").asText());

            String secondStatus = deviceClient.updatePushProvider(newProviderId, newProviderType);
            assertEquals("unchanged", secondStatus);
        } catch (Exception ex) {
            System.err.println("Keycloak container logs:\n" + KEYCLOAK.getLogs());
            throw ex;
        }
    }

    private void completeLoginFlow(DeviceClient deviceClient) throws Exception {
        BrowserSession pushSession = new BrowserSession(baseUri);
        HtmlPage pushLogin = pushSession.startAuthorization("test-app");
        HtmlPage waitingPage = pushSession.submitLogin(pushLogin, "test", "test");
        BrowserSession.DeviceChallenge confirm = pushSession.extractDeviceChallenge(waitingPage);
        deviceClient.respondToChallenge(confirm.confirmToken(), confirm.challengeId());
        pushSession.completePushChallenge(confirm.formAction());
    }

    private DeviceClient enrollDevice() throws Exception {
        return enrollDevice(DeviceKeyType.RSA);
    }

    private DeviceClient enrollDevice(DeviceKeyType keyType) throws Exception {
        adminClient.resetUserState(TEST_USERNAME);
        DeviceState deviceState = DeviceState.create(keyType);
        DeviceClient deviceClient = new DeviceClient(baseUri, deviceState);

        BrowserSession enrollmentSession = new BrowserSession(baseUri);
        HtmlPage loginPage = enrollmentSession.startAuthorization("test-app");
        HtmlPage enrollmentPage = enrollmentSession.submitLogin(loginPage, "test", "test");
        String enrollmentToken = enrollmentSession.extractEnrollmentToken(enrollmentPage);
        deviceClient.completeEnrollment(enrollmentToken);
        enrollmentSession.submitEnrollmentCheck(enrollmentPage);
        return deviceClient;
    }

    private static Path locateProviderJar() {
        Path targetDir = Paths.get("target");
        if (!Files.isDirectory(targetDir)) {
            throw new IllegalStateException("target directory not found. Run mvn package before integration tests.");
        }
        try (var files = Files.list(targetDir)) {
            return files.filter(path -> path.getFileName().toString().startsWith("keycloak-push-mfa")
                            && path.getFileName().toString().endsWith(".jar"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "Provider JAR not found. Run mvn package before integration tests."));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to inspect target directory", ex);
        }
    }
}
