using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace IdP.Web.Features.Admin.Scopes
{
    public class IndexModel : PageModel
    {
        private readonly IOpenIddictScopeManager _scopeManager;

        public IndexModel(IOpenIddictScopeManager scopeManager)
        {
            _scopeManager = scopeManager;
        }

        public List<ScopeViewModel> Scopes { get; set; } = new();

        public async Task OnGetAsync()
        {
            await foreach (var scope in _scopeManager.ListAsync())
            {
                Scopes.Add(new ScopeViewModel
                {
                    Name = await _scopeManager.GetNameAsync(scope),
                    DisplayName = await _scopeManager.GetDisplayNameAsync(scope),
                    Description = await _scopeManager.GetDescriptionAsync(scope),
                });
            }
        }

        public class ScopeViewModel
        {
            public string? Name { get; set; }

            public string? DisplayName { get; set; }

            public string? Description { get; set; }
        }
    }
}
