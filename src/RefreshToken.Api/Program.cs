using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using RefreshToken.Api.Services.Auth; // Added using for ITokenService
using RefreshToken.Api.Services.Auth.Model;
using RefreshToken.Api.Services.Swagger.Model;
using RefreshToken.Data;

var builder = WebApplication.CreateBuilder(args);

// PRODUCTION CONSIDERATION:
// The in-memory database (`UseInMemoryDatabase`) is suitable for development and testing.
// For production, replace this with a persistent database provider (e.g., SQL Server, PostgreSQL, MySQL)
// and ensure proper data backup and security measures are in place.
builder.Services.AddDbContext<RefreshTokenContext>(options => options.UseInMemoryDatabase("RT"));
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<RefreshTokenContext>().AddDefaultTokenProviders();

// Configure AuthSettings for IOptions injection
builder.Services.Configure<AuthSettings>(builder.Configuration.GetSection(nameof(AuthSettings)));

AuthSettings authSettings = builder.Configuration.GetSection(nameof(AuthSettings)).Get<AuthSettings>() ?? throw new ArgumentNullException(nameof(AuthSettings));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = authSettings.Issuer,
        ValidAudience = authSettings.Audience
    };
});

builder.Services.AddAuthorization();

builder.Services.AddMemoryCache();

// PRODUCTION CONSIDERATION:
// For production environments, replace .PersistKeysInMemory() with a more robust and persistent key storage mechanism.
// Options include persisting keys to a database, Azure Key Vault, or other secure storage solutions
// to ensure keys are not lost on application restart and are managed securely.
builder.Services.AddJwksManager().PersistKeysInMemory().UseJwtValidation();

builder.Services.AddScoped<ITokenService, TokenService>(); // Added ITokenService registration

// IdentityModelEventSource.ShowPII = true; // Will be moved down

builder.Services.AddEndpointsApiExplorer();

SwaggerSettings swaggerSettings = builder.Configuration.GetSection(nameof(SwaggerSettings)).Get<SwaggerSettings>() ?? throw new ArgumentNullException(nameof(SwaggerSettings));

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = swaggerSettings.Title,
        Description = swaggerSettings.Description,
        License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Enter the JWT token like this: Bearer {your token}", // Translated to English
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure PII logging for development environment
if (app.Environment.IsDevelopment())
{
    IdentityModelEventSource.ShowPII = true;
}

app.UseAuthentication();

app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapControllers();

app.Run();
