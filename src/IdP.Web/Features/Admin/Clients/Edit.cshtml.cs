using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdP.Web.Features.Admin.Clients
{
    public class EditModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _appManager;
        private readonly IOpenIddictScopeManager _scopeManager;

        public EditModel(IOpenIddictApplicationManager appManager, IOpenIddictScopeManager scopeManager)
        {
            _appManager = appManager;
            _scopeManager = scopeManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public List<string> AvailableResourceScopes { get; set; } = new();

        public async Task<IActionResult> OnGetAsync(string id)
        {
            var app = await _appManager.FindByClientIdAsync(id);
            if(app == null) return NotFound();

            await LoadAvailableScopes();

            var permissions = await _appManager.GetPermissionsAsync(app);
            var redirects = await _appManager.GetRedirectUrisAsync(app);
            var logouts = await _appManager.GetPostLogoutRedirectUrisAsync(app);

            Input = new InputModel
            {
                Id = await _appManager.GetIdAsync(app) ?? "",
                ClientId = await _appManager.GetClientIdAsync(app) ?? "",
                DisplayName = await _appManager.GetDisplayNameAsync(app) ?? "",

                RedirectUris = string.Join(", ", redirects),
                PostLogoutUris = string.Join(", ", logouts),

                // Map Permissions back to Booleans
                FlowAuthCode = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode),
                FlowClientCredentials = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials),
                FlowRefreshToken = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.RefreshToken),

                // Extract custom scopes (remove "scp:" prefix)
                SelectedScopes = permissions
                    .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope))
                    .Select(p => p.Substring(OpenIddictConstants.Permissions.Prefixes.Scope.Length))
                    .ToList()
            };

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                await LoadAvailableScopes();
                return Page();
            }

            var app = await _appManager.FindByIdAsync(Input.Id);
            if (app == null) return NotFound();

            // Determine Client Type
            // If a new secret is set, force Confidential. Otherwise, keep existing type.
            var clientType = await _appManager.GetClientTypeAsync(app) ?? ClientTypes.Public;
            if (!string.IsNullOrWhiteSpace(Input.ClientSecret))
            {
                clientType = ClientTypes.Confidential;
            }

            // Build the descriptor with the new state
            // This descriptor represents the *target state* we want for the application.
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = await _appManager.GetClientIdAsync(app), // Keep existing client id
                DisplayName = Input.DisplayName,
                ClientType = clientType,
                ConsentType = await _appManager.GetConsentTypeAsync(app),
            };

            if (!string.IsNullOrWhiteSpace(Input.ClientSecret))
            {
                descriptor.ClientSecret = Input.ClientSecret;
            }

            // Redirect Uris
            if (!string.IsNullOrWhiteSpace(Input.RedirectUris))
            {
                foreach(var u in Input.RedirectUris.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Uri.TryCreate(u.Trim(), UriKind.Absolute, out var url)) descriptor.RedirectUris.Add(url);
                }
            }

            // Post Logout URIs
            if (!string.IsNullOrWhiteSpace(Input.PostLogoutUris))
            {
                foreach (var u in Input.PostLogoutUris.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Uri.TryCreate(u.Trim(), UriKind.Absolute, out var url)) descriptor.PostLogoutRedirectUris.Add(url);
                }
            }

            // Permissions - Rebuild completely
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

            if (Input.FlowAuthCode)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
                descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
            }

            if (Input.FlowClientCredentials)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            }

            if (Input.FlowRefreshToken)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess);
            }

            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Roles);

            foreach (var scope in Input.SelectedScopes)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
            }

            // Perform the update using the descriptor
            try
            {
                await _appManager.UpdateAsync(app, descriptor);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, $"Update failed: {ex.Message}");
                await LoadAvailableScopes();
                return Page();
            }

            return RedirectToPage("Index");
        }

        private async Task LoadAvailableScopes()
        {
            await foreach (var scope in _scopeManager.ListAsync())
            {
                var name = await _scopeManager.GetNameAsync(scope);
                if(name != null && IsCustomScope(name))
                {
                    AvailableResourceScopes.Add(name);
                }
            }
        }

        private bool IsCustomScope(string scope)
        {
            // Simple filter to hide standard scopes from the "API Access" list
            return scope != OpenIddictConstants.Scopes.OpenId && scope != OpenIddictConstants.Scopes.Email &&
                   scope != OpenIddictConstants.Scopes.Profile && scope != OpenIddictConstants.Scopes.Roles &&
                   scope != OpenIddictConstants.Scopes.OfflineAccess && scope != OpenIddictConstants.Scopes.Phone &&
                   scope != OpenIddictConstants.Scopes.Address;
        }

        public class InputModel
        {
            [Required]
            public string Id { get; set; } = string.Empty;

            public string ClientId { get; set; } = string.Empty; // Read-only for display

            [Required]
            [Display(Name = "Display Name")]
            public string DisplayName { get; set; } = string.Empty;

            [Display(Name = "Client Secret")]
            public string? ClientSecret { get; set; } // Only if changing

            [Display(Name = "Redirect URIs")]
            public string? RedirectUris { get; set; }

            [Display(Name = "Post Logout URIs")]
            public string? PostLogoutUris { get; set; }

            public bool FlowAuthCode { get; set; }
            public bool FlowClientCredentials { get; set; }
            public bool FlowRefreshToken { get; set; }

            public List<string> SelectedScopes { get; set; } = new();
        }
    }
}
