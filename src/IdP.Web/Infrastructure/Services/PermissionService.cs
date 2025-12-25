using System.Security.Claims;
using System.Text.Json;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;

namespace IdP.Web.Infrastructure.Services
{
    public class PermissionService : IPermissionService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IDistributedCache _cache;

        public PermissionService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IDistributedCache cache)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _cache = cache;
        }

        public async Task<List<Claim>> GetPermissionsAsync(ApplicationUser user, IEnumerable<string> scopes)
        {
            // Identify required prefixes
            var requiredPrefixes = scopes
                .Where(s => s.EndsWith("_resource_server", StringComparison.OrdinalIgnoreCase))
                .Select(s => s.Substring(0, s.IndexOf("_resource_server", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (!requiredPrefixes.Any()) return new List<Claim>();

            // Get all permissions
            var allUserPermissions = await GetAllUserPermissionsCachedAsync(user);

            // Filter
            return allUserPermissions
                .Where(p => requiredPrefixes.Any(prefix => p.Value.StartsWith($"{prefix}:", StringComparison.OrdinalIgnoreCase)))
                .ToList();
        }

        public async Task InvalidateCacheAsync(string userId)
        {
            var cacheKey = $"permissions:{userId}";
            await _cache.RemoveAsync(cacheKey);
        }

        private async Task<List<Claim>> GetAllUserPermissionsCachedAsync(ApplicationUser user)
        {
            var cachedKey = $"permissions:{user.Id}";

            // Try cache
            var cachedData = await _cache.GetStringAsync(cachedKey);
            if (!string.IsNullOrEmpty(cachedData))
            {
                var cachedStrings = JsonSerializer.Deserialize<List<string>>(cachedData);
                return cachedStrings?.Select(p => new Claim("permission", p)).ToList() ?? new List<Claim>();
            }

            // Cache miss
            var permissionStrings = new List<string>();
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach ( var roleName in userRoles)
            {
                var role = await _roleManager.FindByNameAsync(roleName);
                if (role != null)
                {
                    var roleClaims = await _roleManager.GetClaimsAsync(role);
                    foreach ( var claim in roleClaims)
                    {
                        if(claim.Type == "permission")
                        {
                            permissionStrings.Add(claim.Value);
                        }
                    }
                }
            }

            var distinctPermissions = permissionStrings.Distinct().ToList();

            // Save to cache
            var options = new DistributedCacheEntryOptions
            {
                SlidingExpiration = TimeSpan.FromMinutes(10)
            };

            var serializedData = JsonSerializer.Serialize(distinctPermissions);
            await _cache.SetStringAsync(cachedKey, serializedData, options);

            return distinctPermissions.Select(p => new Claim("permission", p)).ToList();
        }
    }
}
