using System.ComponentModel.DataAnnotations;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Polly;

namespace IdP.Web.Features.Admin.Permissions
{
    public class EditModel : PageModel
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public EditModel(ApplicationDbContext dbContext, IOpenIddictScopeManager scopeManager, RoleManager<IdentityRole> roleManager)
        {
            _dbContext = dbContext;
            _scopeManager = scopeManager;
            _roleManager = roleManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public List<string> AvailableServices { get; set; } = new();

        public async Task<IActionResult> OnGetAsync(int id)
        {
            var permission = await _dbContext.ServicePermissions.FindAsync(id);
            if(permission == null) return NotFound();

            // Load services
            await LoadServices();

            Input = new InputModel
            {
                Id = permission.Id,
                ServiceId = permission.ClientId,
                Name = permission.Name,
                Value = permission.Value,
                Description = permission.Description,
            };

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                await LoadServices();
                return Page();
            }

            var permission = await _dbContext.ServicePermissions.FindAsync(Input.Id);
            if (permission == null) return NotFound();

            if(permission.Value != Input.Value)
            {
                if(await _dbContext.ServicePermissions.AnyAsync(p => p.Value == Input.Value))
                {
                    ModelState.AddModelError("Input.Value", "This permission value already exists.");
                    await LoadServices();
                    return Page();
                }
            }

            var oldValue = permission.Value;

            permission.ClientId = Input.ServiceId;
            permission.Name = Input.Name;
            permission.Value = Input.Value;
            permission.Description = Input.Description;

            await _dbContext.SaveChangesAsync();

            // Propagation: If the value changed, update all roles that have this claim
            if(oldValue != permission.Value)
            {
                var roles = await _roleManager.Roles.ToListAsync();

                foreach(var role in roles)
                {
                    var claims = await _roleManager.GetClaimsAsync(role);
                    var targetClaim = claims.FirstOrDefault(c => c.Type == "permission" && c.Value == oldValue);

                    if(targetClaim != null)
                    {
                        await _roleManager.RemoveClaimAsync(role, targetClaim);
                        await _roleManager.AddClaimAsync(role, new System.Security.Claims.Claim("permission", Input.Value));
                    }
                }
            }

            return RedirectToPage("Index");
        }

        private async Task LoadServices()
        {
            await foreach (var scope in _scopeManager.ListAsync())
            {
                var name = await _scopeManager.GetNameAsync(scope);
                if(name != null && name.EndsWith("_resource_server"))
                {
                    AvailableServices.Add(name);
                }
            }
        }

        public class InputModel
        {
            [Required]
            public int Id { get; set; }

            [Required]
            [Display(Name = "Services / Resources")]
            public string ServiceId { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Friendly Name")]
            public string Name { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Permission Value")]
            public string Value { get; set; } = string.Empty;

            [Display(Name = "Description")]
            public string? Description { get; set; }
        }
    }
}
