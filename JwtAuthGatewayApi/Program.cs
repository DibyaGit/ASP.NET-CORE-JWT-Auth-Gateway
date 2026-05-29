using System.IdentityModel.Tokens.Jwt;
using System.Text;
using JwtAuthGatewayApi.Authorization;
using JwtAuthGatewayApi.Data;
using JwtAuthGatewayApi.Models;
using JwtAuthGatewayApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthGatewayApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddDataProtection();

            builder.Services.AddSingleton<TokenBlacklistService>();
            builder.Services.AddScoped<TokenService>();

            builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            var secretKey = builder.Configuration["JwtSettings:SecretKey"] ?? "SuperSecretSecureKeyThatIsLongEnoughToMeetSecurityStandards2026!";
            var keyBytes = Encoding.UTF8.GetBytes(secretKey);

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = true;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
                    ValidAudience = builder.Configuration["JwtSettings:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
                    ClockSkew = TimeSpan.Zero
                };
            });

            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("ManagerOrAbove", policy =>
                    policy.RequireRole("SuperAdmin", "Manager"));

                options.AddPolicy("SameUserOrAdmin", policy =>
                    policy.Requirements.Add(new SameUserOrAdminRequirement()));
            });

            builder.Services.AddSingleton<IAuthorizationHandler, SameUserOrAdminHandler>();

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("GatewayCorsPolicy", policy =>
                {
                    policy.AllowAnyOrigin()
                          .AllowAnyMethod()
                          .AllowAnyHeader();
                });
            });

            builder.Services.AddControllers();
            builder.Services.AddOpenApi();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();
            app.UseCors("GatewayCorsPolicy");

            app.Use(async (context, next) =>
            {
                var blacklistService = context.RequestServices.GetRequiredService<TokenBlacklistService>();
                string authHeader = context.Request.Headers.Authorization.ToString();

                if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
                {
                    string token = authHeader.Substring(7);
                    var handler = new JwtSecurityTokenHandler();

                    if (handler.CanReadToken(token))
                    {
                        var jwtToken = handler.ReadJwtToken(token);
                        string jti = jwtToken.Id;

                        if (blacklistService.IsTokenBlacklisted(jti))
                        {
                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsJsonAsync(new
                            {
                                error = "Unauthorized",
                                message = "Token has been invalidated via logout. Please log in again.",
                                code = 401
                            });
                            return;
                        }
                    }
                }
                await next();
            });

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            using (var scope = app.Services.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                string[] roles = { "SuperAdmin", "Manager", "Employee" };
                foreach (var role in roles)
                {
                    if (!roleManager.RoleExistsAsync(role).Result)
                    {
                        roleManager.CreateAsync(new IdentityRole(role)).Wait();
                    }
                }

                if (userManager.FindByNameAsync("superadmin").Result == null)
                {
                    var adminUser = new ApplicationUser { UserName = "superadmin", Email = "admin@company.com" };
                    userManager.CreateAsync(adminUser, "Admin@2026!").Wait();
                    userManager.AddToRoleAsync(adminUser, "SuperAdmin").Wait();
                }
            }

            app.Run();
        }
    }
}