using System.Security.Claims;
using IdP.Web.Infrastructure.Data;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdP.Web.Features.Connect
{
    public class ConnectController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public ConnectController(
            IOpenIddictApplicationManager applicationManager,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager)
        {
            _applicationManager = applicationManager;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        // 1. AUTHORIZE ENDPOINT
        // The user hits this URL to log in. We check if they have a cookie.
        // If yes, we issue an Auth Code. If no, we send them to /Account/Login
        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // Check if user is authenticated in the *Identity* cookie
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

            // IF NOT LOGGED IN: Challenge them (redirect to Login page)
            if (!result.Succeeded || result.Principal is not ClaimsPrincipal principal)
            {
                return Challenge(
                    authenticationSchemes: IdentityConstants.ApplicationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                            Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                    });
            }

            // IF LOGGED IN: Create the Principal (the ticket)
            var user = await _userManager.GetUserAsync(result.Principal);
            if (user == null)
            {
                var userId = _userManager.GetUserId(principal)
                             ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                             ?? principal.FindFirst("sub")?.Value;

                if (userId != null)
                {
                    user = await _userManager.FindByIdAsync(userId);
                }
            }

            if (user == null)
            {
                await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
                return Challenge(IdentityConstants.ApplicationScheme);
            }

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.AddClaim(Claims.Subject, await _userManager.GetUserIdAsync(user!));
            identity.AddClaim(Claims.Name, await _userManager.GetUserNameAsync(user!) ?? "UnidentifiedUser");
            identity.AddClaim(Claims.Email, await _userManager.GetEmailAsync(user!) ?? "");

            // ---------------------------------------------------------------------
            // CUSTOM USER MANAGEMENT LOGIC (AUTHORIZE)
            // ---------------------------------------------------------------------
            // This is where you add permissions specific to the CLIENT being accessed.
            // Example:
            // var permissions = await _myPermissionService.GetPermissionsAsync(user.Id, request.ClientId);
            // foreach (var perm in permissions) { identity.AddClaim("permission", perm); }

            // Explicitly take the scopes from the request and stamp them on the identity.
            // This tells OpenIddict: "Yes, include these scopes in the token."
            identity.SetScopes(request.GetScopes());

            // Wrap the identity in a principal so we can check the scopes inside GetDestinations
            var newPrincipal = new ClaimsPrincipal(identity);

            // Set Destinations (Important for OpenIddict)
            foreach (var claim in identity.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, newPrincipal));
            }

            // Return the SignIn result which OpenIddict intercepts to generate the Auth Code
            return SignIn(newPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // 2. TOKEN ENDPOINT
        // Clients hit this (machine-to-machine) to exchange Code for Token
        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if(request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
            {
                var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                if (!result.Succeeded || result.Principal is null)
                {
                    return Forbid(
                       authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                       properties: new AuthenticationProperties(new Dictionary<string, string?>
                       {
                           [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                           [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                       }));
                }

                var user = await _userManager.GetUserAsync(result.Principal);
                if (user == null)
                {
                    var userId = _userManager.GetUserId(result.Principal)
                            ?? result.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                            ?? result.Principal.FindFirst("sub")?.Value;
                    if (userId != null) user = await _userManager.FindByIdAsync(userId);
                }

                if (user == null || !await _signInManager.CanSignInAsync(user))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                        }));
                }

                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // -----------------------------------------------------------------
                // CUSTOM USER MANAGEMENT LOGIC (REFRESH TOKEN)
                // -----------------------------------------------------------------
                // IMPORTANT: If user permissions changed since the last login, 
                // you should re-fetch them here and update the claims in 'identity'.
                // Otherwise, the refresh token will just copy the old permissions forever.

                identity.AddClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
                identity.AddClaim(Claims.Name, await _userManager.GetUserNameAsync(user) ?? "User");
                identity.AddClaim(Claims.Email, await _userManager.GetEmailAsync(user) ?? "");

                // Set Destinations
                foreach (var claim in identity.Claims)
                {
                    claim.SetDestinations(GetDestinations(claim, result.Principal));
                }

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            else if (request.IsClientCredentialsGrantType())
            {
                if (string.IsNullOrEmpty(request.ClientId))
                {
                    return Forbid(
                       authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                       properties: new AuthenticationProperties(new Dictionary<string, string?>
                       {
                           [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                           [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The client_id is missing."
                       }));
                }

                var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
                if (application == null)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The client application was not found."
                        }));
                }

                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                identity.AddClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application!) ?? "");
                identity.AddClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application!) ?? "");
                identity.SetScopes(request.GetScopes());

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            throw new NotImplementedException("The specified grant type is not implemented.");
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo")]
        [HttpPost("~/connect/userinfo")]
        [IgnoreAntiforgeryToken]
        [Produces("application/json")]
        public async Task<IActionResult> Userinfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                var subject = User.FindFirst(Claims.Subject)?.Value;
                if (!string.IsNullOrEmpty(subject))
                {
                    user = await _userManager.FindByIdAsync(subject);
                }
            }

            if (user is null)
            {
                // Token is valid but the user it belongs to might have been deleted.
                return Challenge(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The specified access token is bound to an account that no longer exists."
                    }));
            }

            // Create the JSON response based on the scopes the token has
            var claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                // 'sub' is mandatory in UserInfo response
                [Claims.Subject] = await _userManager.GetUserIdAsync(user)
            };

            if (User.HasScope(Scopes.Email))
            {
                claims[Claims.Email] = await _userManager.GetEmailAsync(user) ?? "";
                claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
            }

            if (User.HasScope(Scopes.Profile))
            {
                claims[Claims.Name] = await _userManager.GetUserNameAsync(user) ?? "";
                claims[Claims.PreferredUsername] = await _userManager.GetUserNameAsync(user) ?? "";
            }

            if (User.HasScope(Scopes.Roles))
            {
                claims[Claims.Role] = await _userManager.GetRolesAsync(user);
            }

            return Ok(claims);
        }

        // HELPER: Determines where claims live
        private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
        {
            // Note: Destinations decide WHERE the claim appears.
            // AccessToken: Visible to the API.
            // IdentityToken: Visible to the Client (Postman/React) immediately.

            switch (claim.Type)
            {
                case Claims.Name:
                    yield return Destinations.AccessToken;
                    if (principal.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;
                    yield break;

                case Claims.Email:
                    yield return Destinations.AccessToken;
                    if (principal.HasScope(Scopes.Email))
                        yield return Destinations.IdentityToken;
                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;
                    if (principal.HasScope(Scopes.Roles))
                        yield return Destinations.IdentityToken;
                    yield break;

                // Example: Custom permission destination
                case "permission":
                    yield return Destinations.AccessToken;
                    yield break;

                // Never include the security stamp in the tokens, it's a secret
                case "AspNet.Identity.SecurityStamp": yield break;

                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }
    }
}
