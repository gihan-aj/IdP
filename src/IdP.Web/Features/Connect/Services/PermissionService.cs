using System.Security.Claims;
using System.Text.Json;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;

namespace IdP.Web.Features.Connect.Services
{
    public class PermissionService : IPermissionService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IDistributedCache _cache;

        public PermissionService(
            UserManager<ApplicationUser> userManager, 
            RoleManager<IdentityRole> roleManager, 
            IDistributedCache cache)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _cache = cache;
        }

        public async Task<List<Claim>> GetPermissionsAsync(ApplicationUser user, IEnumerable<string> scopes)
        {
            // 1. Identify required prefixes based on scopes (e.g. "ims_resource_server" -> "ims")
            var requiredPrefixes = scopes
                .Where(s => s.EndsWith("_resource_server", StringComparison.OrdinalIgnoreCase))
                .Select(s => s.Substring(0, s.IndexOf("_resource_server", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (!requiredPrefixes.Any()) return new List<Claim>();

            // 2. DEFINE CACHE KEY
            // Key includes UserID and a hash of requested scopes to ensure uniqueness.
            // Sort prefixes to ensure "ims-finance" and "finance-ims" generate the same key.
            requiredPrefixes.Sort();
            var cacheKey = $"permissions:{user.Id}:{string.Join("-", requiredPrefixes)}";

            // 3. TRY GET FROM CACHE (The "Aside" check)
            var cachedData = await _cache.GetStringAsync(cacheKey);
            if (!string.IsNullOrEmpty(cachedData))
            {
                // Cache HIT: Deserialize and return
                // We store strings because Claim objects are tricky to serialize/deserialize directly
                var cachedPermissions = JsonSerializer.Deserialize<List<string>>(cachedData);
                return cachedPermissions?.Select(p => new Claim("permission", p)).ToList() ?? new List<Claim>();
            }

            // 4. CACHE MISS: Calculate from Database (The Expensive Part)
            var claimsToAdd = new List<string>();
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach(var roleName in userRoles)
            {
                var role = await _roleManager.FindByNameAsync(roleName);
                if(role != null)
                {
                    var roleClaims = await _roleManager.GetClaimsAsync(role);
                    foreach(var claim in roleClaims)
                    {
                        if(claim.Type == "permission")
                        {
                            if(requiredPrefixes.Any(prefix => claim.Value.StartsWith($"{prefix}:", StringComparison.OrdinalIgnoreCase)))
                            {
                                claimsToAdd.Add(claim.Value);
                            }
                        }
                    }
                }
            }

            var distinctPermissions = claimsToAdd.Distinct().ToList();

            // 5. SAVE TO CACHE
            var options = new DistributedCacheEntryOptions
            {
                // Keep in cache for 10 minutes.
                // SlidingExpiration: If accessed within 10 mins, reset the timer.
                SlidingExpiration = TimeSpan.FromMinutes(10)
            };

            var serializedData = JsonSerializer.Serialize(distinctPermissions);
            await _cache.SetStringAsync(cacheKey, serializedData, options);

            // 6. Return Result
            return distinctPermissions.Select(p => new Claim("permission", p)).ToList();
        }
    }
}
