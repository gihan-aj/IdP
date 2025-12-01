using IdP.Web.Infrastructure;
using IdP.Web.Infrastructure.Data;
using IdP.Web.Infrastructure.Worker;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages(options =>
{
    options.RootDirectory = "/Features";
});

// Database
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString);
    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict();
});

// Background Worker (Seeder)
builder.Services.AddHostedService<ClientSeederWorker>();

// IDENTITY CONFIGURATION (HEADLESS)
// =============================================================================
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    // Relaxed settings for dev
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 4;

    // User settings
    options.User.RequireUniqueEmail = true;

    // SignIn settings
    options.SignIn.RequireConfirmedAccount = false; // Set to true for email verification flows
});

// OPENIDDICT CONFIGURATION
// =============================================================================
builder.Services.AddOpenIddict()
    // A. Core: Integrate with EF Core to store tokens/apps in DB
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    // B. Server: Handle the OIDC Protocol
    .AddServer(options =>
    {
        // 1. Define the endpoints (matches ConnectController routes)
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetUserInfoEndpointUris("/connect/userinfo");

        // 2. Define flows
        options.AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow()
               .AllowRefreshTokenFlow();

        // 3. Define scopes
        options.RegisterScopes(
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles);

        // 4. Security (Dev only: Ephemeral keys)
        // IN PRODUCTION: Use .AddEncryptionCertificate() and .AddSigningCertificate()
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate()
               .DisableAccessTokenEncryption();

        // 5. ASP.NET Core Integration
        options.UseAspNetCore()
               // We enable "Passthrough" so our ConnectController handles the logic
               // instead of OpenIddict handling it automatically invisibly.
               .EnableTokenEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough();

        if (builder.Environment.IsDevelopment() || Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true")
        {
            options.UseAspNetCore().DisableTransportSecurityRequirement();
        }
    })
    // C. Validation: Needed if this app also consumes tokens (e.g. UserInfo endpoint)
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// CORS
// =============================================================================
builder.Services.AddCors();
builder.Services.AddTransient<ICorsPolicyProvider, DynamicCorsPolicyProvider>();

var app = builder.Build();

// PIPELINE
// =============================================================================
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Standard Routing
app.UseRouting();

// Authentication & Authorization Middleware
app.UseAuthentication();
app.UseAuthorization();

// Map Slices
app.MapControllers(); // Maps the ConnectController
app.MapRazorPages();  // Maps the Login UI

app.Run();
