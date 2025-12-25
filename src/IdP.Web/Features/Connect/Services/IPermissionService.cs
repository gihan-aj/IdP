using System.Security.Claims;
using IdP.Web.Infrastructure.Data;

namespace IdP.Web.Features.Connect.Services
{
    public interface IPermissionService
    {
        Task<List<Claim>> GetPermissionsAsync(ApplicationUser user, IEnumerable<string> scopes);
    }
}
