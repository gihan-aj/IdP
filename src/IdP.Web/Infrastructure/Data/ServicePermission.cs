using System.ComponentModel.DataAnnotations;

namespace IdP.Web.Infrastructure.Data
{
    // This acts as a Catalog of available permissions for an App.
    // When creating Roles, we look at this list to generate checkboxes.
    public class ServicePermission
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string ClientId { get; set; } = string.Empty; // Links to OpenIddict Application

        [Required]
        [StringLength(200)]
        public string Name { get; set; } = string.Empty; // e.g. "Read Products"

        [Required]
        [StringLength(100)]
        public string Value { get; set; } = string.Empty; // e.g. "ims:products:read"

        [StringLength(400)]
        public string? Description { get; set; }
    }
}
