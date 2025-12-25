using System.ComponentModel.DataAnnotations;
using IdP.Web.Infrastructure.Data;
using IdP.Web.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IdP.Web.Features.Admin.Roles
{
    public class EditModel : PageModel
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IPermissionService _permissionService;

        public EditModel(
            RoleManager<IdentityRole> roleManager,
            ApplicationDbContext dbContext,
            UserManager<ApplicationUser> userManager,
            IPermissionService permissionService)
        {
            _roleManager = roleManager;
            _dbContext = dbContext;
            _userManager = userManager;
            _permissionService = permissionService;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public Dictionary<string, List<PermissionItem>> GroupedPermissions { get; set; } = new();

        public async Task<IActionResult> OnGetAsync(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if(role == null) return NotFound();

            // Load current claims
            var currentClaims = await _roleManager.GetClaimsAsync(role);
            var currentPermissions = currentClaims
                .Where(c => c.Type == "permission")
                .Select(c => c.Value)
                .ToHashSet();

            // Load all permission available on db
            var allPermissions = await _dbContext.ServicePermissions.ToListAsync();

            // Group them for UI and mark IsSelected
            GroupedPermissions = allPermissions
                .GroupBy(p => p.ClientId)
                .ToDictionary(
                    g => g.Key,
                    g => g.Select(p => new PermissionItem
                    {
                        Permission = p,
                        IsSelected = currentPermissions.Contains(p.Value)
                    })
                    .ToList()
                );

            Input = new InputModel
            {
                RoleId = role.Id,
                RoleName = role.Name ?? "",
                SelectedPermissions = currentPermissions.ToList()
            };

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return await OnGetAsync(Input.RoleId);
            }

            var role = await _roleManager.FindByIdAsync(Input.RoleId);
            if (role == null) return NotFound();

            bool permissionChanged = false;

            // Update name
            if(role.Name != Input.RoleName)
            {
                role.Name = Input.RoleName;
                await _roleManager.UpdateAsync(role);

                permissionChanged = true;
            }

            // Update permisions
            var currentClaims = await _roleManager.GetClaimsAsync(role);
            var currentPermissionStrings = currentClaims
                .Where(c => c.Type == "permission")
                .Select(c => c.Value)
                .ToList();

            var selected = Input.SelectedPermissions ?? new List<string>();

            var toAdd = selected.Except(currentPermissionStrings);
            var toRemove = currentPermissionStrings.Except(selected);

            // Validation: prevent modifying own permissions
            if(toAdd.Any() || toRemove.Any())
            {
                permissionChanged = true;

                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser is not null)
                {
                    var currentRoles = await _userManager.GetRolesAsync(currentUser);
                    if (currentRoles != null && currentRoles.Contains(role.Name))
                    {
                        ModelState.AddModelError(string.Empty, "Security Alert: You cannot modify your own role permissions. Ask another administrator.");
                        await OnGetAsync(Input.RoleId);
                        return Page();
                    }

                }
            }

            foreach(var p in toAdd)
            {
                await _roleManager.AddClaimAsync(role, new System.Security.Claims.Claim("permission", p));
            }

            foreach (var p in toRemove)
            {
                var claimToRemove = currentClaims.FirstOrDefault(c => c.Type == "permission" && c.Value == p);
                if (claimToRemove != null)
                {
                    await _roleManager.RemoveClaimAsync(role, claimToRemove);
                }
            }

            if (permissionChanged)
            {
                var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name);
                foreach(var user in usersInRole)
                {
                    await _permissionService.InvalidateCacheAsync(user.Id);
                }
            }

            return RedirectToPage("Index");
        }

        public class InputModel
        {
            [Required]
            public string RoleId { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Role Name")]
            public string RoleName { get; set; } = string.Empty;

            public List<string> SelectedPermissions { get; set; } = new();
        }

        public class PermissionItem
        {
            public ServicePermission Permission { get; set; } = new();

            public bool IsSelected { get; set; }
        }
    }
}
