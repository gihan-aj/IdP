using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;

namespace IdP.Web.Infrastructure
{
    public class DynamicCorsPolicyProvider : ICorsPolicyProvider
    {
        private readonly CorsOptions _corsOptions;
        private readonly IServiceProvider _serviceProvider;
        public DynamicCorsPolicyProvider(IOptions<CorsOptions> corsOptions, IServiceProvider serviceProvider)
        {
            _corsOptions = corsOptions.Value;
            _serviceProvider = serviceProvider;
        }

        public async Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
        {
            // 1. If a specific static policy is requested (e.g. [EnableCors("MyPolicy")]), try to find it first.
            if (policyName != null)
            {
                return _corsOptions.GetPolicy(policyName);
            }

            // 2. If no policy name is specified, this is a "Default" CORS request.
            // We will build a dynamic policy based on the Origin header.

            var origin = context.Request.Headers["Origin"].ToString();
            if (string.IsNullOrEmpty(origin))
            {
                return null; // No origin, no CORS needed
            }

            // 3. Resolve the DB Context to check if this Origin is allowed.
            // We use a Scope because this provider is a Singleton, but DbContext is Scoped.
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            // 4. CHECK: Does any registered client have a Redirect URI that starts with this Origin?
            // Note: OpenIddict stores RedirectUris as a JSON array string in the 'RedirectUris' column.
            // This is a naive check. For high performance, you might cache this list in MemoryCache.

            var isAllowed = await dbContext.Set<OpenIddictEntityFrameworkCoreApplication>()
                .AnyAsync(app => !string.IsNullOrEmpty(app.RedirectUris) && app.RedirectUris.Contains(origin));

            if (isAllowed)
            {
                // Build a permissive policy just for this origin
                var policyBuilder = new CorsPolicyBuilder();
                policyBuilder.WithOrigins(origin)
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials(); // Essential for Identity Cookies

                return policyBuilder.Build();
            }

            return null; // Reject
        }
    }
}
