# JwtAuthGatewayApi: Advanced JWT Authentication & Multi-Role API Gateway

A secure, production-grade API Gateway built using **ASP.NET Core 8.0 Web API** designed for a multi-tenant SaaS platform. This gateway centralizes authentication, enforces strict role-based (RBAC) and policy-based authorization layers, protects against sophisticated web vulnerabilities, and secures operational endpoints using state-of-the-art cryptographic standards.

---

# 🚀 Key Features & Security Hardening

## 1. Robust Cryptographic Identity

* **Password Hashing:**
  Leverages ASP.NET Core Identity's PBKDF2 implementation via `UserManager<ApplicationUser>` to ensure secure storage of user credentials.

* **Token Architecture:**
  Generates cryptographically signed JSON Web Tokens (JWT) using HMAC-SHA256 containing essential identity claims:

  * `sub`
  * `unique_name`
  * `email`
  * `role`
  * `jti`

* **Short-Lived Access Tokens:**
  Access tokens are configured to expire in exactly **15 minutes** to minimize intercepted token replay windows.

---

## 2. Session Integrity & Advanced Rotation

* **Data Protection Encryption:**
  Long-lived opaque refresh tokens are encrypted using the **ASP.NET Core Data Protection API** prior to database persistence.

* **Refresh Token Rotation (RTR):**
  Every refresh token exchange revokes the old refresh token and issues a brand-new secure token pair.

* **Instant Logout Blacklisting:**
  Implements high-performance runtime middleware using `TokenBlacklistService` to immediately invalidate logged-out JWT sessions before token expiration.

---

## 3. Policy and Resource-Based Authorization

* **Custom Security Policies:**
  Includes the `ManagerOrAbove` authorization policy for administrative privilege grouping.

* **Resource-Level Isolation:**
  Uses a custom `IAuthorizationHandler` implementation:

  * `SameUserOrAdminHandler`
  * `SameUserOrAdminRequirement`

  Standard users can access only their own records, while `SuperAdmin` users can access all tenant data.

* **Deterministic Security Errors:**
  Returns standardized JSON responses for:

  * `401 Unauthorized`
  * `403 Forbidden`

---

## 4. System Defenses

* **Brute-Force Protection:**
  Locks accounts for **10 minutes** after **5 consecutive failed login attempts** using:

  ```csharp
  UserManager.SetLockoutEndDateAsync()
  ```

* **Transport Security:**
  Enforces:

  * `RequireHttpsMetadata = true`
  * Global HTTPS redirection middleware

* **CORS Restrictions:**
  Accepts requests only from trusted origins configured within security profiles.

---

# 📂 Project Architecture & Directory Layout

```text
JwtAuthGatewayApi/
│
├── Authorization/
│   ├── SameUserOrAdminHandler.cs
│   └── SameUserOrAdminRequirement.cs
│
├── Controllers/
│   ├── AuthController.cs
│   ├── ReportsController.cs
│   ├── TasksController.cs
│   └── UsersController.cs
│
├── Data/
│   └── ApplicationDbContext.cs
│
├── Models/
│   ├── ApplicationUser.cs
│   ├── CreateTaskRequest.cs
│   ├── LoginRequest.cs
│   ├── RefreshRequest.cs
│   ├── RegisterRequest.cs
│   └── UpdateRoleRequest.cs
│
├── Services/
│   ├── TokenBlacklistService.cs
│   └── TokenService.cs
│
├── Program.cs
└── appsettings.json
```

---

# 🌐 API Endpoint Specifications

# 🔑 Authentication Module

---

## 1. User Registration

### Endpoint

```http
POST /api/auth/register
```

### Payload

```json
{
  "username": "alice",
  "email": "alice@company.com",
  "password": "Alice@2026!",
  "role": "Manager"
}
```

### Response — `200 OK`

```json
{
  "message": "User registered successfully with the specified role."
}
```

---

## 2. User Authentication (Login)

### Endpoint

```http
POST /api/auth/login
```

### Payload

```json
{
  "username": "alice",
  "password": "Alice@2026!"
}
```

### Response — `200 OK`

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "HKwB4UsL2PEHZvdOAbZq...",
  "expiresIn": 900,
  "tokenType": "Bearer"
}
```

---

## 3. Cryptographic Token Rotation (Refresh)

### Endpoint

```http
POST /api/auth/refresh
```

### Payload

```json
{
  "expiredAccessToken": "<expired_jwt_string>",
  "refreshToken": "<valid_refresh_token_string>"
}
```

### Response — `200 OK`

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.new...",
  "refreshToken": "RotatedOpaqueTokenString...",
  "expiresIn": 900
}
```

---

## 4. Token Eviction (Logout)

### Endpoint

```http
POST /api/auth/logout
```

### Headers

```http
Authorization: Bearer <access_token>
```

### Response — `200 OK`

```json
{
  "message": "Logged out successfully. Token context has been invalidated."
}
```

---

# 👥 User & Operational Directories

| Endpoint                    | HTTP Verb | Security Policy / Role    | Description                             |
| --------------------------- | --------- | ------------------------- | --------------------------------------- |
| `/api/users`                | GET       | `SuperAdmin` Only         | Fetches all system users                |
| `/api/users/{id}`           | GET       | `SuperAdmin` OR Same User | Retrieves individual user profile       |
| `/api/users/{id}/role`      | PUT       | `SuperAdmin` Only         | Updates role assignments                |
| `/api/reports/team-summary` | GET       | `ManagerOrAbove` Policy   | Returns operational performance reports |
| `/api/tasks/my`             | GET       | Any Authenticated User    | Retrieves personalized task records     |
| `/api/tasks`                | POST      | Employee or Higher        | Creates task records                    |

---

# 🛠️ Local Machine Setup Instructions

## Prerequisites

* .NET 8.0 SDK
* Visual Studio 2022

  * ASP.NET and web development workload enabled

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/your-username/JwtAuthGatewayApi.git

cd JwtAuthGatewayApi
```

---

## Step 2 — Restore Dependencies

```bash
dotnet restore
```

---

## Step 3 — Initialize Database Schema

The application supports:

* In-memory database mode
* Local SQL database configuration

Apply migrations if required:

```bash
dotnet ef database update
```

---

## Step 4 — Launch the Application

```bash
dotnet run --project JwtAuthGatewayApi
```

The application will start and display the runtime address:

```text
http://localhost:5000
```

---

# 🧪 Operational Scenario Testing Pipeline

The project includes a built-in Visual Studio HTTP client file:

```text
JwtAuthGatewayApi.http
```

## Testing Workflow

1. Open `JwtAuthGatewayApi.http`
2. Verify the `@Hostname` variable matches your runtime port
3. Execute:

   * `POST /api/auth/register`
   * `POST /api/auth/login`
4. Capture the generated JWT token
5. Insert the token into:

   ```http
   Authorization: Bearer <token>
   ```
6. Test protected endpoints to validate:

   * Role-based access control
   * Policy enforcement
   * `401 Unauthorized`
   * `403 Forbidden`

---

# 🔐 Security Highlights

* ASP.NET Core Identity Integration
* PBKDF2 Password Hashing
* JWT Authentication
* Refresh Token Rotation
* Role-Based Authorization (RBAC)
* Policy-Based Authorization
* Resource-Based Authorization
* Token Blacklisting
* HTTPS Enforcement
* CORS Restrictions
* Lockout Protection
* Data Protection API Encryption

---

# 🧱 Technology Stack

| Technology                | Purpose                          |
| ------------------------- | -------------------------------- |
| ASP.NET Core 8.0          | Backend API Framework            |
| Entity Framework Core     | ORM & Database Access            |
| ASP.NET Core Identity     | Authentication & User Management |
| JWT Bearer Authentication | Stateless Access Security        |
| Data Protection API       | Refresh Token Encryption         |
| SQL Server / In-Memory DB | Data Storage                     |

---

# 📄 License

This project is developed as an academic and professional proof-of-concept for advanced software system gateways.

All implementations are designed with enterprise-grade architectural patterns, production-level security hardening, and modern API security standards.
