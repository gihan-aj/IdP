using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IdP.Web.Features.Admin.Roles
{
    public class IndexModel : PageModel
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public IndexModel(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        public List<IdentityRole> Roles { get; set; } = new();

        public async Task OnGetAsync()
        {
            Roles = await _roleManager.Roles.OrderBy(r => r.Name).ToListAsync();
        }
    }
}
