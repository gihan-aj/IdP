
using System.Security.Claims;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace IdP.Web.Infrastructure.Worker
{
    public class ClientSeederWorker : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public ClientSeederWorker(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            // -------------------------------------------------------------------------
            // 1. ROBUST MIGRATION STRATEGY
            // -------------------------------------------------------------------------
            var retries = 10;
            while (retries > 0)
            {
                try
                {
                    // Attempt to apply migrations
                    await context.Database.MigrateAsync(cancellationToken);
                    break; // Success, Exit loop
                }
                catch (SqlException ex) when (ex.Number == 1801)
                {
                    // ERROR 1801: "Database already exists"
                    // Cause: Race condition. EF thought DB was missing, tried to create it, but it was there.
                    // FIX: Do NOT break. Retry! 
                    // Next time we call MigrateAsync, EF will see the DB exists and skip creation,
                    // moving straight to applying the migrations.

                    retries--;
                    if (retries == 0) throw;
                    await Task.Delay(2000, cancellationToken);
                }
                catch(Exception)
                {
                    // Any other error (e.g. Connection Refused because SQL is still starting)
                    retries--;
                    if (retries == 0) throw;

                    // Wait 2 seconds before trying again
                    await Task.Delay(2000, cancellationToken);
                }
            }

            // -------------------------------------------------------------------------
            // 2. SEEDING LOGIC
            // -------------------------------------------------------------------------
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            // A. SEED SCOPES (The "Resource Server" Definitions)
            if(await scopeManager.FindByNameAsync("ims_resource_server", cancellationToken) is null)
            {
                await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "ims_resource_server",
                    DisplayName = "IMS API",
                    Description = "Access the Inventory management system.",
                    Resources =
                    {
                        "ims_backend_api" // Optional: Validates the 'aud' claim for the resource server
                    }
                }, cancellationToken);
            }

            // B. SEED CLIENTS

            // 1. Angular/React Client
            if (await appManager.FindByClientIdAsync("ims-angular-client", cancellationToken) is null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "ims-angular-client",
                    ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                    DisplayName = "Angular Client",
                    RedirectUris = { new Uri("http://localhost:4200/callback") },
                    PostLogoutRedirectUris = { new Uri("http://localhost:4200/") },
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.EndSession,
                        OpenIddictConstants.Permissions.Endpoints.Token,

                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                        OpenIddictConstants.Permissions.ResponseTypes.Code,

                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Roles,
                        OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
                    
                        // Add the Custom Scope Permission using the prefix constant
                        OpenIddictConstants.Permissions.Prefixes.Scope + "ims_resource_server"
                    },
                    Requirements =
                    {
                        OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                    }
                }, cancellationToken);
            }

            // 2. Postman Client
            if (await appManager.FindByClientIdAsync("postman", cancellationToken) is null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "postman",
                    ClientSecret = "postman-secret",
                    DisplayName = "Postman",
                    RedirectUris = { new Uri("https://oauth.pstmn.io/v1/callback") },
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                        OpenIddictConstants.Permissions.ResponseTypes.Code,
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Roles,
                    
                        // Allow Postman to test IMS scope too
                        OpenIddictConstants.Permissions.Prefixes.Scope + "ims_resource_server"
                    },
                    Requirements =
                    {
                        OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                    }
                }, cancellationToken);
            }

            // 3. Console Client (M2M)
            if (await appManager.FindByClientIdAsync("console", cancellationToken) is null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "console",
                    ClientSecret = "console-secret",
                    DisplayName = "Console App",
                    Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                    // Give machine access to IMS
                    OpenIddictConstants.Permissions.Prefixes.Scope + "ims_resource_server"
                }
                }, cancellationToken);
            }
            

            if (await appManager.FindByClientIdAsync("pos-client", cancellationToken) is null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "pos-client",
                    // No Secret for PKCE Public Clients
                    ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                    DisplayName = "POS System",
                    RedirectUris = { new Uri("http://127.0.0.1:7890/callback") },
                    PostLogoutRedirectUris = { new Uri("http://127.0.0.1:7890/") },
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.EndSession,
                        OpenIddictConstants.Permissions.Endpoints.Token,

                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                        OpenIddictConstants.Permissions.ResponseTypes.Code,

                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Roles,

                        OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
                    },
                    Requirements =
                    {
                        OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                    }
                }, cancellationToken);
            }

            // C. SEED ROLES & PERMISSIONS
            if (await roleManager.FindByNameAsync("User") is null)
            {
                var role = new IdentityRole("User");
                await roleManager.CreateAsync(role);
            }

            if (await roleManager.FindByNameAsync("Manager") is null)
            {
                var role = new IdentityRole("Manager");
                await roleManager.CreateAsync(role);

                // These permissions are prefixed with 'ims:' by convention
                await roleManager.AddClaimAsync(role, new Claim("permission", "ims:products:read"));
                await roleManager.AddClaimAsync(role, new Claim("permission", "ims:products:create"));
                await roleManager.AddClaimAsync(role, new Claim("permission", "ims:products:edit"));
            }

            // D. SEED USER
            if (await userManager.FindByNameAsync("bob") is null)
            {
                var user = new ApplicationUser
                {
                    UserName = "bob",
                    Email = "bob@test.com",
                    EmailConfirmed = true
                };

                await userManager.CreateAsync(user, "Pass123$");
                await userManager.AddToRoleAsync(user, "Manager");
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
