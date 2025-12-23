using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace IdP.Web.Features.Admin.Permissions
{
    public class IndexModel : PageModel
    {
        private readonly ApplicationDbContext _dbContext;

        public IndexModel(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public List<PermissionViewModel> Permissions { get; set; } = new();

        public async Task OnGetAsync()
        {
            Permissions = await _dbContext.ServicePermissions
                .Select(p => new PermissionViewModel
                {
                    Id = p.Id,
                    ServiceId = p.ClientId,
                    Name = p.Name,
                    Value = p.Value,
                    Description = p.Description,
                })
                .OrderBy(p => p.ServiceId)
                .ThenBy(p => p.Value)
                .ToListAsync();
        }

        public class PermissionViewModel
        {
            public int Id { get; set; }

            public string ServiceId { get; set; } = string.Empty;

            public string Name { get; set; } = string.Empty;

            public string Value { get; set; } = string.Empty;

            public string? Description { get; set; }
        }
    }
}
