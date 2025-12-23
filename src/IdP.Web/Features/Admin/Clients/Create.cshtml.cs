using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdP.Web.Features.Admin.Clients
{
    public class CreateModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;

        public CreateModel(IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public List<string> AvailableResourceScopes { get; set; } = new();

        public async Task OnGetAsync()
        {
            await foreach (var scope in _scopeManager.ListAsync())
            {
                var name = await _scopeManager.GetNameAsync(scope);
                if(name != null && !IsStandardScope(name))
                {
                    AvailableResourceScopes.Add(name);
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

            if(await _applicationManager.FindByClientIdAsync(Input.ClientId) != null)
            {
                ModelState.AddModelError("Input.ClientId", "This Client ID is already taken.");
                await OnGetAsync();
                return Page();
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = Input.ClientId,
                DisplayName = Input.DisplayName,
                ClientSecret = Input.ClientSecret,
                ConsentType = ConsentTypes.Explicit,
            };

            // 1. URLs
            if (!string.IsNullOrWhiteSpace(Input.RedirectUris))
            {
                foreach(var uri in Input.RedirectUris.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var url))
                        descriptor.RedirectUris.Add(url);
                }
            }
            
            if (!string.IsNullOrWhiteSpace(Input.PostLogoutUris))
            {
                foreach(var uri in Input.PostLogoutUris.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var url))
                        descriptor.PostLogoutRedirectUris.Add(url);
                }
            }

            // 2. PERMISSIONS - FLOWS

            // Base endpoints
            descriptor.Permissions.Add(Permissions.Endpoints.Token);

            if (Input.FlowAuthCode)
            {
                descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
                descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                descriptor.Permissions.Add(Permissions.ResponseTypes.Code);

                // PKCE is standard for auth code
                descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
            }

            if (Input.FlowClientCredentials)
            {
                descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
            }

            if (Input.FlowRefreshToken)
            {
                descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess);
            }

            // 3. PERMISSIONS - STANDARD SCOPES
            descriptor.Permissions.Add(Permissions.Scopes.Email);
            descriptor.Permissions.Add(Permissions.Scopes.Profile);
            descriptor.Permissions.Add(Permissions.Scopes.Roles);

            // 4. PERMISSIONS - CUSTOM RESOURCE SCOPES (From Checkboxes)
            foreach (var scope in Input.SelectedScopes)
            {
                // We use the Prefix constant to ensure correct format: "scp:scope_name"
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
            }

            await _applicationManager.CreateAsync(descriptor);

            return RedirectToPage("Index");

        }

        public class InputModel
        {
            [Required]
            [Display(Name = "Client ID")]
            public string ClientId { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Display Name")]
            public string DisplayName { get; set; } = string.Empty;

            [Display(Name = "Client Secret")]
            public string? ClientSecret {  get; set; }

            [Display(Name = "Redirect URIs (comma separated)")]
            public string? RedirectUris { get; set; }

            [Display(Name = "Post Logout URIs (comma separated")]
            public string? PostLogoutUris { get; set; }

            // --- FLOWS ---
            [Display(Name = "Allow Authorization Code Flow (Interactive)")]
            public bool FlowAuthCode { get; set; } = true;

            [Display(Name = "Allow Client Credentials Flow (Machine-to-Machine)")]
            public bool FlowClientCredentials { get; set; }

            [Display(Name = "Allow Refresh Tokens")]
            public bool FlowRefreshToken { get; set; } = true;

            // --- SCOPES ---
            public List<string> SelectedScopes { get; set; } = new();
        }

        private bool IsStandardScope(string scope)
        {
            return scope == OpenIddictConstants.Scopes.OpenId ||
                   scope == OpenIddictConstants.Scopes.Email ||
                   scope == OpenIddictConstants.Scopes.Profile ||
                   scope == OpenIddictConstants.Scopes.Roles ||
                   scope == OpenIddictConstants.Scopes.OfflineAccess ||
                   scope == OpenIddictConstants.Scopes.Phone ||
                   scope == OpenIddictConstants.Scopes.Address;
        }
    }
}
