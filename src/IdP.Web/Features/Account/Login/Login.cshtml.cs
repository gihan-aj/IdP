using System.ComponentModel.DataAnnotations;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdP.Web.Features.Account.Login
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;

        public LoginModel(SignInManager<ApplicationUser> signInManager)
        {
            _signInManager = signInManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [BindProperty(SupportsGet = true)]
        public string? ReturnUrl { get; set; }

        public class InputModel
        {
            [Required]
            public string Username { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; } = string.Empty;
        }

        public async Task OnGetAsync(string? returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // 1. Validate Input
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // 2. Attempt Login
            // Note: For learning, we are using Username. 
            // In production, you might want to allow Email or Username.
            var result = await _signInManager.PasswordSignInAsync(
                Input.Username,
                Input.Password,
                isPersistent: false, // "Remember Me" can be added here later
                lockoutOnFailure: false);

            if (result.Succeeded)
            {
                // 3. Success!
                // This is the most critical part of an IdP Login:
                // We MUST redirect back to the 'ReturnUrl'.
                // The ReturnUrl contains the '/connect/authorize?client_id=...' query.
                // Redirecting there triggers the ConnectController we built earlier,
                // which sees the cookie we just created, and issues the tokens.

                // Security Check: Ensure the return URL is local to prevent Open Redirect attacks
                if (Url.IsLocalUrl(ReturnUrl))
                {
                    return LocalRedirect(ReturnUrl);
                }

                return RedirectToAction("Index", "Home");
            }

            // 4. Failure
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }
    }
}
