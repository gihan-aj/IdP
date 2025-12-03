
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

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            // 1. Machine-to-Machine Client (e.g., a backend service)
            if (await manager.FindByClientIdAsync("console", cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "console",
                    ClientSecret = "console-secret",
                    DisplayName = "Console App",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
                    }
                }, cancellationToken);
            }

            // 2. Interactive Client (e.g., React/Angular/Blazor)
            if (await manager.FindByClientIdAsync("react-app", cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "react-app",
                    // No Secret for PKCE Public Clients
                    ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                    DisplayName = "React Application",
                    RedirectUris = { new Uri("https://localhost:3000/callback") },
                    PostLogoutRedirectUris = { new Uri("https://localhost:3000/") },
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.EndSession,
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.ResponseTypes.Code,
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Roles
                    },
                    Requirements =
                    {
                        OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                    }
                }, cancellationToken);
            }
            
            if (await manager.FindByClientIdAsync("ims-angular-client", cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "ims-angular-client",
                    // No Secret for PKCE Public Clients
                    ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                    DisplayName = "IMS Angular Client",
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

                        // Allow accessing the IMS API and getting user profile info
                        OpenIddictConstants.Permissions.Prefixes.Scope + "ims_resource_server",
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Roles
                    },
                    Requirements =
                    {
                        OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                    }
                }, cancellationToken);
            }

            // 3. Postman Client (For Testing)
            if (await manager.FindByClientIdAsync("postman", cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
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
                        OpenIddictConstants.Permissions.Scopes.Roles
                    },
                    // We allow PKCE but don't strictly require it for Postman flexibility
                    Requirements =
                    {
                        OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                    }
                }, cancellationToken);
            }

            // 4. Seed Test User
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            if (await userManager.FindByNameAsync("bob") is null)
            {
                var user = new ApplicationUser
                {
                    UserName = "bob",
                    Email = "bob@test.com",
                    EmailConfirmed = true
                };

                // Note: In real apps, password complexity rules apply. 
                // We relaxed them in Program.cs for dev.
                await userManager.CreateAsync(user, "Pass123$");
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
