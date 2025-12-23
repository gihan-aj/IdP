using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace IdP.Web.Features.Admin.Clients
{
    public class IndexModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _openIddictApplicationManager;

        public IndexModel(IOpenIddictApplicationManager openIddictApplicationManager)
        {
            _openIddictApplicationManager = openIddictApplicationManager;
        }

        public List<ClientViewModel> Clients { get; set; } = new();

        public async Task OnGetAsync()
        {
            await foreach (var app in _openIddictApplicationManager.ListAsync())
            {
                Clients.Add(new ClientViewModel
                {
                    Id = await _openIddictApplicationManager.GetIdAsync(app),
                    ClientId = await _openIddictApplicationManager.GetClientIdAsync(app),
                    DisplayName = await _openIddictApplicationManager.GetDisplayNameAsync(app),
                    RedirectUriCount = (await _openIddictApplicationManager.GetRedirectUrisAsync(app)).Count()
                });
            }
        }

        public class ClientViewModel
        {
            public string? Id { get; set; }

            public string? ClientId { get; set; }

            public string? DisplayName { get; set; }

            public int RedirectUriCount { get; set; }
        }
    }
}
