using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IdP.Web.Features.Admin.Roles
{
    public class CreateModel : PageModel
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _dbContext;

        public CreateModel(RoleManager<IdentityRole> roleManager, ApplicationDbContext dbContext)
        {
            _roleManager = roleManager;
            _dbContext = dbContext;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        // Permissions grouped by Service Name (Scope) for the UI
        public Dictionary<string, List<ServicePermission>> GroupedPermissions { get; set; } = new();

        public async Task OnGetAsync()
        {
            var permissions = await _dbContext.ServicePermissions.ToListAsync();
            GroupedPermissions = permissions
                .GroupBy(p => p.ClientId) // ClientId stores the Service Name (e.g., "ims_resource_server")
                .ToDictionary(g => g.Key, g => g.ToList());
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                await OnGetAsync();
                return Page();
            }

            if (await _roleManager.RoleExistsAsync(Input.RoleName))
            {
                ModelState.AddModelError("Input.RoleName", "Role already exists.");
                await OnGetAsync();
                return Page();
            }

            // 1. Create Role
            var role = new IdentityRole(Input.RoleName);
            var result = await _roleManager.CreateAsync(role);

            if (result.Succeeded)
            {
                // 2. Assign Claims (Permissions)
                foreach (var permValue in Input.SelectedPermissions)
                {
                    // We add them as type "permission" so our ConnectController logic picks them up!
                    await _roleManager.AddClaimAsync(role, new Claim("permission", permValue));
                }

                return RedirectToPage("Index");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await OnGetAsync();
            return Page();
        }

        public class InputModel
        {
            [Required]
            [Display(Name = "Role Name")]
            public string RoleName { get; set; } = string.Empty;

            // List of selected Permission Values (e.g. "ims:products:read")
            public List<string> SelectedPermissions { get; set; } = new();
        }
    }
}
