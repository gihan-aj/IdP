# Modern OpenIddict Identity Provider (.NET 10)

A production-ready, headless Identity Provider (IdP) built with **ASP.NET Core 10** and **OpenIddict**. This project demonstrates a robust implementation of OAuth 2.0 and OpenID Connect (OIDC) using **Vertical Slice Architecture**.

It features a full-fledged **Admin Portal** for dynamic configuration of Clients, Scopes, and Permissions, moving away from hardcoded configuration to a database-driven approach.

## 🚀 Features

### Core Identity & Security
* **Headless Architecture:** Custom Login, Register, and Consent screens using **Razor Pages** and **Tailwind CSS** (No dependency on `Identity.UI`).
* **Standard Flows:** Supports Authorization Code (PKCE), Client Credentials, and Refresh Token flows.
* **Dynamic CORS:** Database-driven CORS policy that automatically allows registered Client origins.
* **Persistent Consent:** "Remember My Decision" functionality using OpenIddict Authorizations.

### Authorization Engine (RBAC/ABAC)
* **Dynamic Permissions:** A custom Permission Catalog allowing granular control (e.g., `finance:invoices:approve`).
* **Scope-Based Injection:** Automatically injects permissions into Access Tokens based on the requested Scope (e.g., asking for `ims_resource_server` loads `ims:*` claims).
* **Role Management:** Assign permissions to Roles via the Admin UI.

### Admin Portal
A complete dashboard to manage the OIDC ecosystem without touching code:
* **User Management:** List, Edit, and Assign Roles.
* **Client Management:** Register new Applications (SPA, Machine-to-Machine) and configure flows/redirects.
* **Scope Management:** Define new Resource Servers (APIs).
* **Permission Catalog:** Create permissions manually or **bulk import via JSON**.

## 🛠️ Technology Stack
* **.NET 10** (ASP.NET Core)
* **OpenIddict 7.x** (Server & Validation)
* **Entity Framework Core** (SQL Server)
* **Razor Pages** (UI)
* **Tailwind CSS** (Styling via CDN)
* **Docker & Docker Compose**

## 📂 Project Structure
The project follows **Vertical Slice Architecture**, organizing code by Feature rather than technical layer:

```text
src/MyIdP.Web/
├── Features/
│   ├── Account/        # Login, Register, Access Denied logic
│   ├── Admin/          # Admin Portal (Clients, Users, Roles, Scopes)
│   ├── Connect/        # OIDC Protocol Endpoints (Authorize, Token, UserInfo)
│   ├── Home/           # Dashboard
│   └── Shared/         # Layouts
├── Infrastructure/     # Database context, Seeders, Background Workers
└── Program.cs          # Composition Root
```

## 🐳 Getting Started (Docker)
The easiest way to run the solution is using Docker Compose, which spins up the App and a SQL Server instance.

**1. Clone the repository:**
```bash
git clone [https://github.com/your-username/my-idp.git](https://github.com/your-username/my-idp.git)
cd my-idp
```

**2. Run with Docker Compose:**
```bash
docker compose up --build
```

**3. Access the App:**
* **Dashboard:** http://localhost:8080
* **Discovery Document:** http://localhost:8080/.well-known/openid-configuration

##⚡ Default Credentials (Seeder)
On the first run, the `ClientSeederWorker` initializes the database with test data:

* User: `admin`

* Password: `Pass123$`

* Role: `Admin`r (Has `ims:*` permissions)

Note: To access the Admin Portal (`/admin/users`), you must have the `Admin` role. You may need to manually assign this role to your user via the database or modify `ClientSeederWorker.cs`.

# 🧪 Testing with Postman
1. **Grant Type:** Authorization Code

2. **Auth URL:** `http://localhost:8080/connect/authorize`

3. **Token URL:** `http://localhost:8080/connect/token`

4. **Client ID:** `postman`

5. **Client Secret:** `postman-secret`

6. **Scope:** `openid profile email offline_access ims_resource_server`

7. **PKCE:** Enabled (SHA-256)

# 🔧 Configuration Guide

**Adding a New API (Resource Server)**

1. Go to **Admin > Scopes**.

2. Create a new Scope (e.g., `finance`). The system automatically creates `finance_resource_server`.

3. Go to **Admin > Permissions**.

4. Add permissions linked to that service (e.g., `finance:invoices:read`).

5. Assign these permissions to a **Role**.

6. Register a **Client** and check the `finance_resource_server` box in "API Access".

**Bulk Importing Permissions**

You can upload a JSON file at `/admin/permissions/import` to setup a new environment quickly:

```json
{
  "finance_resource_server": [
    { "name": "View Invoices", "value": "finance:invoices:read" },
    { "name": "Pay Invoices", "value": "finance:invoices:pay" }
  ]
}
```

# 📝 License
