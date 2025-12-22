using System.ComponentModel.DataAnnotations;

namespace IdP.Web.Features.Connect
{
    public class ConsentViewModel
    {
        [Display(Name = "Application")]
        public string ApplicationName { get; set; } = string.Empty;

        [Display(Name = "Scope")]
        public IEnumerable<string> Scopes { get; set; } = new List<string>();

        public string ReturnUrl { get; set; } = string.Empty;
    }
}
