using System.ComponentModel.DataAnnotations;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IdP.Web.Features.Admin.Users
{
    public class EditModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public EditModel(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public string Username { get; set; } = string.Empty;

        // Available roles
        public List<string> AllRoles { get; set; } = new();

        public class InputModel
        {
            [Required]
            public string Id { get; set; } = string.Empty;

            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            public List<string> SelectedRoles { get; set; } = new();
        }

        public async Task<IActionResult> OnGetAsync(string id)
        {
            var user =  await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();
            var userRoles = (await _userManager.GetRolesAsync(user)).ToList() ?? [];

            Username = user.UserName ?? "";

            // Load user data
            Input = new InputModel
            {
                Id = id,
                Email = user.Email ?? "",
                SelectedRoles = userRoles
            };

            // All system roles
            AllRoles = await _roleManager.Roles.Select(r => r.Name!).ToListAsync();

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            AllRoles = await _roleManager.Roles.Select(r => r.Name!).ToListAsync();

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // VALIDATION 1: Ensure at least one role is selected
            if (!Input.SelectedRoles.Any())
            {
                ModelState.AddModelError(string.Empty, "At least one role must be selected to prevent orphan accounts.");
                return Page();
            }

            var user = await _userManager.FindByIdAsync(Input.Id);
            if (user == null) return NotFound();

            // VALIDATION 2: Prevent modifying own roles (Self-Lockout Protection)
            var currentUserId = _userManager.GetUserId(User);
            if (user.Id == currentUserId)
            {
                var existingUserRoles = await _userManager.GetRolesAsync(user);

                // Check if the set of roles has changed
                bool rolesChanged = !new HashSet<string>(existingUserRoles).SetEquals(Input.SelectedRoles);

                if (rolesChanged)
                {
                    ModelState.AddModelError(string.Empty, "Security Alert: You cannot modify your own roles. Ask another administrator.");
                    return Page();
                }
            }

            // 1. Update Basic Info
            if (Input.Email != user.Email)
            {
                user.Email = Input.Email;
                user.UserName = Input.Email;
                await _userManager.UpdateAsync(user);
            }

            // 2. Manage Roles
            var currentRoles = await _userManager.GetRolesAsync(user);
            var selectedRoles = Input.SelectedRoles ?? new List<string>();

            var toAdd = selectedRoles.Except(currentRoles);
            var toRemove = currentRoles.Except(selectedRoles);

            if (toAdd.Any()) await _userManager.AddToRolesAsync(user, toAdd);
            if (toRemove.Any()) await _userManager.RemoveFromRolesAsync(user, toRemove);

            // 3. Security: Refresh User's Security Stamp
            if (toAdd.Any() || toRemove.Any())
            {
                await _userManager.UpdateSecurityStampAsync(user);
            }

            return RedirectToPage("Index");
        }
    }
}
