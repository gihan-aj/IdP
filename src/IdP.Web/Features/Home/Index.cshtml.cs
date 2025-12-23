using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdP.Web.Features.Home
{
    [Authorize]
    public class IndexModel : PageModel
    {
        public string Username { get; set; } = string.Empty;

        public IEnumerable<string> Claims { get; set; } = new List<string>();

        public void OnGet()
        {
            Username = User.Identity?.Name ?? "Unknown";

            Claims = User.Claims
                .Select(c => $"{c.Type}: {c.Value}")
                .ToList();
        }
    }
}
