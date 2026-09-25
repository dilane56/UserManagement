package com.cbcbourse.usermanagement.iam;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
class IamIntegrationTest {

    private static final String ADMIN_EMAIL = "admin@test.local";
    private static final String ADMIN_PASSWORD = "Admin123!";
    private static final String USER_PASSWORD = "Password123";

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void protectedEndpointWithoutTokenReturns401Json() throws Exception {
        mvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.path").value("/api/users"));
    }

    @Test
    void invalidTokenReturns401() throws Exception {
        mvc.perform(get("/api/users").header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Token invalide"));
    }

    @Test
    void adminLoginReturnsTokensAndAllPermissions() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(ADMIN_EMAIL, ADMIN_PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.user.roles[0]").value("ADMIN"))
                .andExpect(jsonPath("$.user.permissions.length()").value(9));
    }

    @Test
    void wrongPasswordReturns401() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(ADMIN_EMAIL, "wrong-password")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Identifiants invalides"));
    }

    @Test
    void passwordIsNeverExposed() throws Exception {
        String admin = accessToken(ADMIN_EMAIL, ADMIN_PASSWORD);
        String body = perform(get("/api/users"), admin).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("password").contains(ADMIN_EMAIL);
    }

    @Test
    void validationErrorsAreReportedPerField() throws Exception {
        String admin = accessToken(ADMIN_EMAIL, ADMIN_PASSWORD);
        perform(post("/api/users").contentType(MediaType.APPLICATION_JSON)
                .content("{\"nom\":\"\",\"prenom\":\"x\",\"email\":\"pas-un-email\",\"password\":\"123\"}"), admin)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.nom").exists())
                .andExpect(jsonPath("$.fieldErrors.email").exists())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    @Test
    void userWithoutPermissionIsForbiddenUntilRoleGrantsIt() throws Exception {
        String admin = accessToken(ADMIN_EMAIL, ADMIN_PASSWORD);
        String email = uniqueEmail();
        long userId = createUser(admin, email, List.of());

        String user = accessToken(email, USER_PASSWORD);
        perform(get("/api/users"), user).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Accès refusé"));
        perform(get("/api/auth/me"), user).andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value("USER"));

        // Nouveau rôle avec USER_READ, attribué à l'utilisateur
        String roleCode = "AUDITOR_" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        perform(post("/api/roles").contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"" + roleCode + "\",\"name\":\"Auditeur\",\"permissions\":[\"USER_READ\"]}"), admin)
                .andExpect(status().isCreated());
        perform(put("/api/users/" + userId + "/roles").contentType(MediaType.APPLICATION_JSON)
                .content("{\"roles\":[\"USER\",\"" + roleCode + "\"]}"), admin)
                .andExpect(status().isOk());

        // Le même token donne désormais accès : les droits sont relus en base à chaque requête
        perform(get("/api/users"), user).andExpect(status().isOk());
        perform(delete("/api/users/" + userId), user).andExpect(status().isForbidden());
    }

    @Test
    void refreshTokenRotationAndReuseDetection() throws Exception {
        String login = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(ADMIN_EMAIL, ADMIN_PASSWORD)))
                .andReturn().getResponse().getContentAsString();
        String firstRefresh = JsonPath.read(login, "$.refreshToken");

        String refreshed = mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody(firstRefresh)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String secondRefresh = JsonPath.read(refreshed, "$.refreshToken");
        assertThat(secondRefresh).isNotEqualTo(firstRefresh);

        // Réutilisation de l'ancien token => refusé, et toutes les sessions sont révoquées
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(firstRefresh)))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(secondRefresh)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRevokesRefreshToken() throws Exception {
        String login = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(ADMIN_EMAIL, ADMIN_PASSWORD)))
                .andReturn().getResponse().getContentAsString();
        String refresh = JsonPath.read(login, "$.refreshToken");

        mvc.perform(post("/api/auth/logout").contentType(MediaType.APPLICATION_JSON).content(refreshBody(refresh)))
                .andExpect(status().isNoContent());
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshBody(refresh)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void disabledUserIsRejectedImmediately() throws Exception {
        String admin = accessToken(ADMIN_EMAIL, ADMIN_PASSWORD);
        String email = uniqueEmail();
        long userId = createUser(admin, email, List.of());
        String user = accessToken(email, USER_PASSWORD);

        perform(patch("/api/users/" + userId + "/status").contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":false}"), admin).andExpect(status().isOk());

        perform(get("/api/auth/me"), user).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Compte désactivé"));
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(email, USER_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminCannotDeleteOrDisableItself() throws Exception {
        String admin = accessToken(ADMIN_EMAIL, ADMIN_PASSWORD);
        String me = perform(get("/api/auth/me"), admin).andReturn().getResponse().getContentAsString();
        Number adminId = JsonPath.read(me, "$.id");

        perform(delete("/api/users/" + adminId), admin).andExpect(status().isBadRequest());
        perform(patch("/api/users/" + adminId + "/status").contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":false}"), admin).andExpect(status().isBadRequest());
    }

    @Test
    void superAdminRoleIsProtected() throws Exception {
        String admin = accessToken(ADMIN_EMAIL, ADMIN_PASSWORD);
        String roles = perform(get("/api/roles"), admin).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        List<Number> adminRoleIds = JsonPath.read(roles, "$[?(@.code == 'ADMIN')].id");

        perform(delete("/api/roles/" + adminRoleIds.get(0)), admin).andExpect(status().isBadRequest());
        perform(put("/api/roles/" + adminRoleIds.get(0) + "/permissions").contentType(MediaType.APPLICATION_JSON)
                .content("{\"permissions\":[]}"), admin).andExpect(status().isBadRequest());
    }

    @Test
    void duplicateEmailReturns409() throws Exception {
        String admin = accessToken(ADMIN_EMAIL, ADMIN_PASSWORD);
        String email = uniqueEmail();
        createUser(admin, email, List.of());
        perform(post("/api/users").contentType(MediaType.APPLICATION_JSON)
                .content(userBody(email.toUpperCase(), List.of())), admin)
                .andExpect(status().isConflict());
    }

    @Test
    void changePasswordRevokesSessionsAndRequiresCurrentPassword() throws Exception {
        String admin = accessToken(ADMIN_EMAIL, ADMIN_PASSWORD);
        String email = uniqueEmail();
        createUser(admin, email, List.of());
        String user = accessToken(email, USER_PASSWORD);

        perform(put("/api/auth/me/password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"mauvais\",\"newPassword\":\"NewPassword123\"}"), user)
                .andExpect(status().isBadRequest());
        perform(put("/api/auth/me/password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"" + USER_PASSWORD + "\",\"newPassword\":\"NewPassword123\"}"), user)
                .andExpect(status().isNoContent());

        accessToken(email, "NewPassword123");
    }

    @Test
    void registrationCreatesUserWithDefaultRole() throws Exception {
        String email = uniqueEmail();
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nom\":\"Doe\",\"prenom\":\"Jane\",\"email\":\"" + email + "\",\"password\":\"" + USER_PASSWORD + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.roles[0]").value("USER"));
    }

    @Test
    void openApiDocumentationIsAvailable() throws Exception {
        mvc.perform(get("/v3/api-docs")).andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/users']").exists());
    }

    // ---------------------------------------------------------------- helpers

    private ResultActions perform(MockHttpServletRequestBuilder request, String token) throws Exception {
        return mvc.perform(request.header("Authorization", "Bearer " + token));
    }

    private String accessToken(String email, String password) throws Exception {
        String body = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(credentials(email, password)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.accessToken");
    }

    private long createUser(String adminToken, String email, List<String> roles) throws Exception {
        String body = perform(post("/api/users").contentType(MediaType.APPLICATION_JSON)
                .content(userBody(email, roles)), adminToken)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return ((Number) JsonPath.read(body, "$.id")).longValue();
    }

    private static String userBody(String email, List<String> roles) {
        String rolesJson = roles.stream().map(r -> "\"" + r + "\"").reduce((a, b) -> a + "," + b).orElse("");
        return "{\"nom\":\"Test\",\"prenom\":\"User\",\"email\":\"" + email + "\",\"password\":\"" + USER_PASSWORD
                + "\",\"roles\":[" + rolesJson + "]}";
    }

    private static String credentials(String email, String password) {
        return "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
    }

    private static String refreshBody(String refreshToken) {
        return "{\"refreshToken\":\"" + refreshToken + "\"}";
    }

    private static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@test.local";
    }
}
