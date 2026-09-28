# UserManagement : socle IAM (utilisateurs, rôles, permissions)

Application Spring Boot servant de **base réutilisable** pour vos projets : authentification JWT,
gestion des utilisateurs et contrôle d'accès par rôles et permissions (RBAC).
On clone ce socle puis on ajoute ses modules métier à côté.

- Spring Boot 4.1, Java 17, Spring Security 7, JPA (Hibernate 7)
- JWT d'accès court + refresh token avec rotation et détection de vol
- Permissions déclarées dans le code par chaque module, rôles gérés par API
- SQL Server par défaut, JPA standard (PostgreSQL ou MySQL en changeant le driver)
- Swagger UI : `http://localhost:9001/swagger-ui.html`

---

## 1. Démarrage rapide

1. Créer la base (`usermanagementdb`) et renseigner les variables d'environnement (voir `.env.example`),
   au minimum `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` et `JWT_SECRET` (`openssl rand -base64 64`).
2. Lancer : `./mvnw spring-boot:run`
3. Au premier démarrage, le socle crée automatiquement :
   - les permissions déclarées dans le code,
   - les rôles `ADMIN` (toutes les permissions) et `USER`,
   - le compte admin `IAM_ADMIN_EMAIL`. Si `IAM_ADMIN_PASSWORD` est vide, le mot de passe généré s'affiche **une seule fois** dans les logs.
4. `POST /api/auth/login` puis utiliser `Authorization: Bearer <accessToken>`.

Tests : `./mvnw test` (base H2 en mémoire, aucun SQL Server nécessaire).

---

## 2. Architecture

Le code est organisé **par fonctionnalité**. Un nouveau module s'ajoute comme un package frère de `iam`.

```
com.cbcbourse.usermanagement
├── common/                  Transverse, réutilisable par tous les modules
│   ├── config/              Audit JPA (created_by...), OpenAPI
│   ├── dto/PageResponse     Format de pagination
│   ├── exception/           ApiException, NotFound, Conflict, BadRequest, handler global
│   └── model/BaseEntity     id + created_at/updated_at/created_by/updated_by
├── security/                JWT, filtre, SecurityConfig, UserPrincipal, SecurityUtils, IamProperties
└── iam/                     Module IAM
    ├── auth/                login, refresh, logout, register, /me
    ├── user/                CRUD utilisateurs, rôles, statut, mot de passe
    ├── role/                CRUD rôles, permissions d'un rôle
    ├── permission/          Permission, PermissionProvider, IamPermissions
    ├── token/               Refresh tokens (hachés en base)
    └── bootstrap/           Initialisation des données au démarrage
```

### Modèle de données

```
iam_users ──< iam_user_roles >── iam_roles ──< iam_role_permissions >── iam_permissions
    └──< iam_refresh_tokens
```

Toutes les tables du socle sont préfixées `iam_` pour ne pas entrer en collision avec vos tables métier.

### Autorités Spring Security

Un utilisateur connecté porte :
- ses rôles sous la forme `ROLE_<CODE>`, vérifiés avec `hasRole('ADMIN')` ;
- ses permissions (codes bruts), vérifiées avec `hasAuthority('USER_READ')`. **C'est ce qu'il faut privilégier.**

Les droits sont relus en base à chaque requête. Désactiver un compte ou retirer un rôle prend donc effet
immédiatement, sans attendre l'expiration du token.

---

## 3. API

| Méthode | Route | Permission |
|---|---|---|
| POST | `/api/auth/login` | public |
| POST | `/api/auth/refresh` | public (refresh token) |
| POST | `/api/auth/logout` | public (refresh token) |
| POST | `/api/auth/register` | public, si `IAM_REGISTRATION_ENABLED=true` |
| GET / PUT | `/api/auth/me` | authentifié |
| PUT | `/api/auth/me/password` | authentifié |
| GET | `/api/users?search=&page=&size=&sort=` | `USER_READ` |
| GET | `/api/users/{id}`, `/api/users/by-email?email=` | `USER_READ` |
| POST | `/api/users` | `USER_CREATE` |
| PUT | `/api/users/{id}` | `USER_UPDATE` |
| PATCH | `/api/users/{id}/status` | `USER_UPDATE` |
| PUT | `/api/users/{id}/roles` | `USER_UPDATE` |
| PUT | `/api/users/{id}/password` | `USER_UPDATE` |
| DELETE | `/api/users/{id}` | `USER_DELETE` |
| GET | `/api/roles`, `/api/roles/{id}` | `ROLE_READ` |
| POST | `/api/roles` | `ROLE_CREATE` |
| PUT | `/api/roles/{id}`, `/api/roles/{id}/permissions` | `ROLE_UPDATE` |
| DELETE | `/api/roles/{id}` | `ROLE_DELETE` |
| GET | `/api/permissions` | `PERMISSION_READ` |

Garde-fous intégrés :
- on ne peut ni se supprimer ni se désactiver soi-même ;
- le dernier administrateur actif ne peut être ni supprimé, ni désactivé, ni privé du rôle `ADMIN` ;
- le rôle `ADMIN` reçoit toujours toutes les permissions et n'est pas modifiable ;
- les rôles système et les rôles encore attribués ne peuvent pas être supprimés ;
- changer ou réinitialiser un mot de passe, ou désactiver un compte, révoque ses refresh tokens.

Toutes les erreurs ont le même format :
```json
{ "timestamp": "...", "status": 400, "error": "Bad Request", "message": "Données invalides",
  "path": "/api/users", "fieldErrors": { "email": "Email invalide" } }
```

---

## 4. Réutiliser ce socle dans un nouveau projet

### Option A : cloner et changer de dépôt distant (recommandée)

```bash
git clone <url-de-ce-depot> mon-nouveau-projet
cd mon-nouveau-projet
git remote rename origin socle          # garder le lien vers le socle
git remote add origin <url-du-nouveau-depot>
git push -u origin main
```

L'intérêt de garder le remote `socle` : quand vous améliorez le socle (correctif de sécurité, nouvelle
fonctionnalité), vous pouvez le récupérer dans vos projets avec `git fetch socle && git merge socle/main`.
Pour limiter les conflits, évitez de modifier `common/`, `security/` et `iam/` dans les projets :
personnalisez plutôt par `application.yml` et par vos propres packages.

### Option B : dépôt « template » GitHub ou GitLab

Marquez ce dépôt comme *Template repository* (GitHub : Settings → Template repository).
Le bouton **Use this template** crée alors un nouveau dépôt propre, sans l'historique.

### Personnaliser le projet cloné

1. `pom.xml` : `groupId`, `artifactId`, `name`, `description`.
2. `application.yml` : `spring.application.name` (sert aussi d'émetteur JWT), rôles de départ.
3. Facultatif : renommer le package `com.cbcbourse.usermanagement` (refactoring « Rename package » de l'IDE).

---

## 5. Ajouter un module métier

Exemple d'un module `portfolio` :

```
com.cbcbourse.usermanagement.portfolio
├── PortfolioPermissions.java
├── Portfolio.java            (extends BaseEntity)
├── PortfolioRepository.java
├── PortfolioService.java
└── PortfolioController.java
```

**1. Déclarer les permissions du module.** Elles sont créées en base au démarrage et le rôle `ADMIN` les reçoit automatiquement.

```java
@Component
public class PortfolioPermissions implements PermissionProvider {
    public static final String PORTFOLIO_READ = "PORTFOLIO_READ";
    public static final String PORTFOLIO_WRITE = "PORTFOLIO_WRITE";

    @Override
    public Collection<PermissionDefinition> permissions() {
        return List.of(
            new PermissionDefinition(PORTFOLIO_READ, "Consulter les portefeuilles", "PORTFOLIO"),
            new PermissionDefinition(PORTFOLIO_WRITE, "Gérer les portefeuilles", "PORTFOLIO"));
    }
}
```

**2. Protéger les endpoints.**

```java
@GetMapping
@PreAuthorize("hasAuthority('" + PortfolioPermissions.PORTFOLIO_READ + "')")
public List<PortfolioResponse> findAll() { ... }
```

**3. Récupérer l'utilisateur connecté dans un service.**

```java
Long userId = SecurityUtils.requireCurrentUserId();
boolean canWrite = SecurityUtils.hasPermission(PortfolioPermissions.PORTFOLIO_WRITE);
```

**4. Lever des erreurs homogènes** : `ResourceNotFoundException.of("Portefeuille", id)`,
`new ConflictException(...)`, `new BadRequestException(...)`.

**5. Donner les droits à d'autres rôles** : via l'API (`PUT /api/roles/{id}/permissions`) ou,
pour un rôle créé au premier démarrage, dans `iam.bootstrap.roles` :

```yaml
iam:
  bootstrap:
    roles:
      - code: GESTIONNAIRE
        name: Gestionnaire de portefeuille
        permissions: [PORTFOLIO_READ, PORTFOLIO_WRITE, USER_READ]
```

**6. Endpoints publics du module** : `iam.security.public-paths: ["/api/public/**"]`.

---

## 6. Changer de base de données

Le code n'utilise que JPA standard :
1. dans `pom.xml`, remplacer la dépendance `mssql-jdbc` par `postgresql` ou `mysql-connector-j` (déjà présentes en commentaire) ;
2. adapter `DB_URL`.

Hibernate détecte le dialecte automatiquement.

## 7. Production

- `JPA_DDL_AUTO=validate`, avec un outil de migration (Flyway ou Liquibase) pour versionner le schéma.
- `JWT_SECRET` fort et propre à chaque environnement ; `IAM_ADMIN_PASSWORD` défini, puis changé après la première connexion.
- `CORS_ALLOWED_ORIGINS` limité aux domaines du front.
