using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using RefreshToken.Api.Services.Auth.Model;
using RefreshToken.Api.Services.Swagger.Model;
using RefreshToken.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<RefreshTokenContext>(options => options.UseInMemoryDatabase("RT"));
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<RefreshTokenContext>().AddDefaultTokenProviders();

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

builder.Services.AddJwksManager().PersistKeysInMemory().UseJwtValidation();

IdentityModelEventSource.ShowPII = true;

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
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
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
