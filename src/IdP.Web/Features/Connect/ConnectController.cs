using System.Collections.Immutable;
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
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public ConnectController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IOpenIddictScopeManager scopeManager)
        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _scopeManager = scopeManager;
        }

        // -------------------------------------------------------------------------
        // AUTHORIZE ENDPOINT
        // -------------------------------------------------------------------------
        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            // 1. Validate the OIDC Request
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // 2. Authenticate the User (Check Cookie)
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

            // If not logged in, redirect to login page
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

            // 3. Retrieve the User Object
            // We do this once and reuse 'user' throughout the method.
            var user = await _userManager.GetUserAsync(principal);
            if (user == null)
            {
                // Fallback: Try fetching by ID from claims if standard lookup fails
                var userId = _userManager.GetUserId(principal)
                        ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                        ?? principal.FindFirst("sub")?.Value;

                if (userId != null) user = await _userManager.FindByIdAsync(userId);
            }

            if (user == null)
            {
                // If we still can't find the user, their account might be deleted. Log them out.
                await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
                return Challenge(IdentityConstants.ApplicationScheme);
            }

            // 4. Retrieve the Client Application
            // We validate this EARLY so we can rely on 'application' being non-null later.
            var clientId = request.ClientId ??
                throw new InvalidOperationException("Client ID cannot be found.");
            var application = await _applicationManager.FindByClientIdAsync(clientId) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            var applicationId = await _applicationManager.GetIdAsync(application) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
            var userIdString = await _userManager.GetUserIdAsync(user);

            // 5. Handle Consent Form Submission (POST)
            // If the user clicked "Allow" or "Deny" on the Consent View
            if (Request.HasFormContentType)
            {
                var consentAction = Request.Form["consent_action"].ToString();

                if (consentAction == "deny")
                {
                    return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                if (consentAction == "accept")
                {
                    // Create the permanent authorization
                    // We use the already-retrieved 'user' and 'application' variables here.
                    await _authorizationManager.CreateAsync(
                        principal: principal,
                        subject: userIdString,
                        client: applicationId,
                        type: AuthorizationTypes.Permanent,
                        scopes: request.GetScopes());

                    // Continue execution flow to issue the token...
                }
            }

            // 6. Check for Existing Authorizations
            var authorizations = await _authorizationManager.FindAsync(
                subject: userIdString,
                client: applicationId,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes()).ToListAsync();

            // 7. Determine Consent Requirements
            var consentType = await _applicationManager.GetConsentTypeAsync(application);

            // If explicit consent is required and no authorization exists, show the View.
            if (consentType != ConsentTypes.Implicit && !authorizations.Any())
            {
                return View("~/Features/Connect/Consent.cshtml", new ConsentViewModel
                {
                    ApplicationName = await _applicationManager.GetDisplayNameAsync(application) ?? "Unknown Application",
                    Scopes = request.GetScopes(),
                    ScopeDescriptions = await GetScopeDescriptions(request.GetScopes()),
                    ReturnUrl = Request.PathBase + Request.Path + QueryString.Create(
                            Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
            }

            // 8. Construct the Identity Ticket
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.AddClaim(Claims.Subject, userIdString);
            identity.AddClaim(Claims.Name, await _userManager.GetUserNameAsync(user) ?? user.UserName ?? "Unknown User");
            identity.AddClaim(Claims.Email, await _userManager.GetEmailAsync(user) ?? "");

            identity.SetScopes(request.GetScopes());

            // 9. Inject Permissions (Dynamic based on scopes)
            var permissions = await GetPermissionsForScopesAsync(user, request.GetScopes());
            foreach (var claim in permissions)
            {
                identity.AddClaim(claim);
            }

            var newPrincipal = new ClaimsPrincipal(identity);

            // Attach the authorization ID so OpenIddict knows this token is backed by a DB entry
            newPrincipal.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorizations.LastOrDefault()!));

            foreach (var claim in identity.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, newPrincipal));
            }

            return SignIn(newPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // -------------------------------------------------------------------------
        // TOKEN EXCHANGE ENDPOINT
        // -------------------------------------------------------------------------
        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // Case A: Authorization Code or Refresh Token
            if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
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

                // Copy existing claims from the ticket
                var identity = new ClaimsIdentity(result.Principal.Claims,
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Dynamic Permission Refresh
                // If the scope indicates a resource server, we wipe and re-fetch permissions to ensure they are fresh.
                var grantedScopes = result.Principal.GetScopes();

                if (grantedScopes.Any(s => s.EndsWith("_resource_server", StringComparison.OrdinalIgnoreCase)))
                {
                    // Clear old permissions
                    var existingPermissions = identity.Claims.Where(c => c.Type == "permission").ToList();
                    foreach (var claim in existingPermissions) identity.RemoveClaim(claim);

                    // Fetch new permissions
                    var freshPermissions = await GetPermissionsForScopesAsync(user, grantedScopes);
                    foreach (var claim in freshPermissions)
                    {
                        // Add only if not duplicate
                        if (!identity.HasClaim(c => c.Type == claim.Type && c.Value == claim.Value))
                        {
                            identity.AddClaim(claim);
                        }
                    }
                }

                // Re-apply destinations (OpenIddict does not persist destinations in Auth Codes)
                foreach (var claim in identity.Claims)
                {
                    claim.SetDestinations(GetDestinations(claim, result.Principal));
                }

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // Case B: Client Credentials (Machine-to-Machine)
            else if (request.IsClientCredentialsGrantType())
            {
                var application = await _applicationManager.FindByClientIdAsync(request.ClientId ?? "");
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

                // Handle potentially null Client properties safely
                var clientId = await _applicationManager.GetClientIdAsync(application);
                var displayName = await _applicationManager.GetDisplayNameAsync(application);

                identity.AddClaim(Claims.Subject, clientId ?? "Unknown");
                identity.AddClaim(Claims.Name, displayName ?? clientId ?? "Unknown");

                identity.SetScopes(request.GetScopes());

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            throw new NotImplementedException("The specified grant type is not implemented.");
        }

        // -------------------------------------------------------------------------
        // USERINFO ENDPOINT
        // -------------------------------------------------------------------------
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
                if (!string.IsNullOrEmpty(subject)) user = await _userManager.FindByIdAsync(subject);
            }

            if (user is null)
            {
                return Challenge(
                   authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                   properties: new AuthenticationProperties(new Dictionary<string, string?>
                   {
                       [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                       [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The specified access token is bound to an account that no longer exists."
                   }));
            }

            var claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
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

        // -------------------------------------------------------------------------
        // LOGOUT ENDPOINT
        // -------------------------------------------------------------------------
        [HttpGet("~/connect/logout")]
        [HttpPost("~/connect/logout")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties { RedirectUri = "/" });
        }

        // -------------------------------------------------------------------------
        // HELPER METHODS
        // -------------------------------------------------------------------------

        /// <summary>
        /// Dynamically loads permissions based on the requested resource scopes.
        /// E.g. "ims_resource_server" -> loads all claims starting with "ims:" from the user's roles.
        /// </summary>
        private async Task<List<Claim>> GetPermissionsForScopesAsync(ApplicationUser user, IEnumerable<string> scopes)
        {
            var claimsToAdd = new List<Claim>();

            var requiredPrefixes = scopes
                .Where(s => s.EndsWith("_resource_server", StringComparison.OrdinalIgnoreCase))
                .Select(s => s.Substring(0, s.IndexOf("_resource_server", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (!requiredPrefixes.Any()) return claimsToAdd;

            var userRoles = await _userManager.GetRolesAsync(user);
            if (userRoles == null) return claimsToAdd;

            foreach (var roleName in userRoles)
            {
                var role = await _roleManager.FindByNameAsync(roleName);
                if (role != null)
                {
                    var roleClaims = await _roleManager.GetClaimsAsync(role);
                    if (roleClaims == null) continue;

                    // Filter claims: Must be type "permission" AND start with one of the prefixes
                    foreach (var claim in roleClaims)
                    {
                        if (claim.Type == "permission")
                        {
                            if (requiredPrefixes.Any(prefix => claim.Value.StartsWith($"{prefix}:", StringComparison.OrdinalIgnoreCase)))
                            {
                                claimsToAdd.Add(claim);
                            }
                        }
                    }
                }
            }

            // Return distinct claims
            return claimsToAdd
                .GroupBy(c => c.Value)
                .Select(g => g.First())
                .ToList();
        }

        private async Task<IEnumerable<string>> GetScopeDescriptions(IEnumerable<string> scopes)
        {
            var descriptions = new List<string>();

            foreach (var scope in scopes)
            {
                // 1. Try to find the scope in the Database via OpenIddictScopeManager
                var scopeEntity = await _scopeManager.FindByNameAsync(scope);
                if (scopeEntity != null)
                {
                    // Retrieve the description or display name from the DB
                    var description = await _scopeManager.GetDescriptionAsync(scopeEntity);
                    var displayName = await _scopeManager.GetDisplayNameAsync(scopeEntity);

                    // Add the best available friendly string
                    descriptions.Add(description ?? displayName ?? $"Access the '{scope}' scope");
                    continue;
                }

                // 2. Fallback for Standard OIDC Scopes (if not seeded in DB)
                // It is best practice to seed these too, but this switch ensures the UI is always friendly.
                var standardDescription = scope switch
                {
                    OpenIddictConstants.Scopes.Email => "View your email address",
                    OpenIddictConstants.Scopes.Profile => "View your basic profile details (name, username)",
                    OpenIddictConstants.Scopes.Roles => "View your assigned roles",
                    OpenIddictConstants.Scopes.OfflineAccess => "Access your data even when you are not logged in",
                    OpenIddictConstants.Scopes.OpenId => "Sign you in using your identity",
                    _ => $"Access the '{scope}' scope" // Final fallback
                };

                descriptions.Add(standardDescription);
            }

            return descriptions;
        }

        private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
        {
            switch (claim.Type)
            {
                case Claims.Name:
                    yield return Destinations.AccessToken;
                    if (principal.HasScope(Scopes.Profile)) yield return Destinations.IdentityToken;
                    yield break;

                case Claims.Email:
                    yield return Destinations.AccessToken;
                    if (principal.HasScope(Scopes.Email)) yield return Destinations.IdentityToken;
                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;
                    if (principal.HasScope(Scopes.Roles)) yield return Destinations.IdentityToken;
                    yield break;

                case "permission":
                    yield return Destinations.AccessToken;
                    yield break;

                case "AspNet.Identity.SecurityStamp": yield break;

                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }
    }
}
