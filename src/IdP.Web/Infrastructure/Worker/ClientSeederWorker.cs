
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
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
            await context.Database.EnsureCreatedAsync(cancellationToken);

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
