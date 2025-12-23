using System.ComponentModel.DataAnnotations;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace IdP.Web.Features.Admin.Permissions
{
    public class CreateModel : PageModel
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly IOpenIddictScopeManager _scopeManager;

        public CreateModel(ApplicationDbContext dbContext, IOpenIddictScopeManager scopeManager)
        {
            _dbContext = dbContext;
            _scopeManager = scopeManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        // List of Scopes to use as the "Service" group
        public List<string> AvailableServices { get; set; } = new();

        public async Task OnGetAsync()
        {
            // Load custom resource scopes (ending in _resource_server)
            await foreach (var scope in _scopeManager.ListAsync())
            {
                var name = await _scopeManager.GetNameAsync(scope);
                if (name != null && name.EndsWith("_resource_server"))
                {
                    AvailableServices.Add(name);
                }
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                await OnGetAsync();
                return Page();
            }

            // Check for duplicates
            // We allow same value if it belongs to a different service (unlikely, but possible)
            // But strictly, the Value string (claim) should be unique across the system to avoid confusion.
            var exists = _dbContext.ServicePermissions.Any(p => p.Value == Input.Value);
            if (exists)
            {
                ModelState.AddModelError("Input.Value", "This permission value already exists.");
                await OnGetAsync();
                return Page();
            }

            var permission = new ServicePermission
            {
                ClientId = Input.ServiceId,
                Name = Input.Name,
                Value = Input.Value,
                Description = Input.Description
            };

            _dbContext.ServicePermissions.Add(permission);
            await _dbContext.SaveChangesAsync();

            return RedirectToPage("Index");
        }

        public class InputModel
        {
            [Required]
            [Display(Name = "Service / Resource")]
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
