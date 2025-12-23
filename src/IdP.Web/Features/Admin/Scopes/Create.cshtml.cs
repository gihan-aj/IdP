using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace IdP.Web.Features.Admin.Scopes
{
    public class CreateModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;

        public CreateModel(IOpenIddictScopeManager scopeManager)
        {
            _scopeManager = scopeManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var scopeName = Input.Name.EndsWith("_resource_server")
                ? Input.Name
                : $"{Input.Name}_resource_server";

            if(await _scopeManager.FindByNameAsync(scopeName) != null)
            {
                ModelState.AddModelError("Input.Name", "This scope name already exists.");
                return Page();
            }

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = scopeName,
                DisplayName = Input.DisplayName,
                Description = Input.Description,
                Resources = { Input.ResourceId } // This sets the 'aud' claim
            };

            await _scopeManager.CreateAsync(descriptor);

            return RedirectToPage("Index");
        }

        public class InputModel
        {
            [Required]
            [Display(Name = "Resource Name")]
            [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Only letters, numbers, and underscores allowed.")]
            public string Name { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Display Name")]
            public string DisplayName { get; set; } = string.Empty;

            [Display(Name = "Description")]
            public string? Description { get; set; }

            [Required]
            [Display(Name = "Audience ID (Resource Name)")]
            public string ResourceId { get; set; } = string.Empty;
        }
    }
}
