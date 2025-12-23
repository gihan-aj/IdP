using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IdP.Web.Features.Admin.Users
{
    public class IndexModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public IndexModel(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public List<UserViewModel> Users { get; set; } = new();

        public async Task OnGetAsync()
        {
            var users = await _userManager.Users.ToListAsync();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                Users.Add(new UserViewModel
                {
                    Id = user.Id,
                    Username = user.UserName ?? "Unknown",
                    Email = user.Email ?? "Unknown",
                    Roles = string.Join(",", roles)
                });
            }
        }

        public class UserViewModel
        {
            public string Id { get; set; } = string.Empty;

            public string Username { get; set; } = string.Empty;

            public string Email { get; set; } = string.Empty;

            public string Roles {  get; set; } = string.Empty;
        }
    }
}
