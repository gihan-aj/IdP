using System.Security.Claims;
using IdP.Web.Infrastructure.Data;

namespace IdP.Web.Infrastructure.Services
{
    public interface IPermissionService
    {
        /// <summary>
        /// Retrieves permissions for a user, filtered by the requested scopes.
        /// Uses caching to minimize database hits.
        /// </summary>
        Task<List<Claim>> GetPermissionsAsync(ApplicationUser user, IEnumerable<string> scopes);

        /// <summary>
        /// Invalidates the permission cache for a specific user.
        /// Call this when roles or permissions change.
        /// </summary>
        Task InvalidateCacheAsync(string userId);
    }
}
