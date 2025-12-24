using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Polly;

namespace IdP.Web.Features.Admin.Permissions
{
    public class ImportModel : PageModel
    {
        private readonly ApplicationDbContext _dbContext;

        public ImportModel(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        [BindProperty]
        [Required]
        [Display(Name = "Permission JSON File")]
        public IFormFile? UploadFile { get; set; }

        public string Message { get; set; } = string.Empty;

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid || UploadFile == null) return Page();

            try
            {
                using var stream = UploadFile.OpenReadStream();
                // Expected JSON Format:
                // {
                //    "ims_resource_server": [
                //       { "name": "Create Product", "value": "ims:products:create", "description": "..." }
                //    ]
                // }
                var data = await JsonSerializer
                    .DeserializeAsync<Dictionary<string, List<PermissionDto>>>(
                        stream, 
                        new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true,
                        }
                    );

                if(data == null)
                {
                    ModelState.AddModelError(string.Empty, "Invalid JSON format.");
                    return Page();
                }

                int addedCount = 0;
                int skippedCount = 0;

                foreach(var serviceKey in data.Keys)
                {
                    var permissions = data[serviceKey];
                    foreach(var permDto in permissions)
                    {
                        // Check duplicates
                        if(await _dbContext.ServicePermissions.AnyAsync(p => p.Value == permDto.Value))
                        {
                            skippedCount++;
                            continue;
                        }

                        var entity = new ServicePermission
                        {
                            ClientId = serviceKey,
                            Name = permDto.Name,
                            Value = permDto.Value,
                            Description = permDto.Description,
                        };

                        _dbContext.ServicePermissions.Add(entity);
                        addedCount++;
                    }
                }

                await _dbContext.SaveChangesAsync();
                Message = $"Success! Added {addedCount} permissions. Skipped {skippedCount} duplicates.";
                return Page(); // Stay on page to show message
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, $"Error parsing file: {ex.Message}");
                return Page();
            }
        }

        public class PermissionDto
        {
            public string Name { get; set; } = "";
            public string Value { get; set; } = "";
            public string? Description { get; set; }
        }
    }
}
