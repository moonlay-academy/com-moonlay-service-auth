using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Com.Moonlay.Service.Auth.WebApi.Data;
using Com.Moonlay.Service.Auth.WebApi.Models;
using Com.Moonlay.Service.Auth.WebApi.Services;
using System.Linq;
using System.Reflection;
using IdentityServer4.Models;
using IdentityServer4;
using System.Net.NetworkInformation;
using System.Net;
using Com.Moonlay.Service.Auth.WebApi.Middlewares.CSP;

namespace Com.Moonlay.Service.Auth.WebApi
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);
            if (env.IsDevelopment())
            {
                // For more details on using the user secret store see https://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets<Startup>();
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var connectionString = Configuration.GetConnectionString("DefaultConnection") ?? Configuration["DefaultConnection"];
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.AddMvc();

            // Add application services.
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();

            // Adds IdentityServer
            IIdentityServerBuilder isBuilder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseSuccessEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseErrorEvents = true;
            });
            BuildEntityFrameworkIdentityServer(isBuilder);
        }
        void BuildEntityFrameworkIdentityServer(IIdentityServerBuilder idsrvBuilder)
        {
            var connectionString = Configuration.GetConnectionString("DefaultConnection") ?? Configuration["DefaultConnection"];
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            idsrvBuilder.AddTemporarySigningCredential()

              .AddConfigurationStore(builder =>
                  builder.UseSqlServer(connectionString, options =>
                      options.MigrationsAssembly(migrationsAssembly)))

              .AddOperationalStore(builder =>
                  builder.UseSqlServer(connectionString, options =>
                      options.MigrationsAssembly(migrationsAssembly)))

              .AddAspNetIdentity<ApplicationUser>();
        }


        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            // this will do the initial DB population
            InitializeDatabase(app, env, loggerFactory);

            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseCsp(builder =>
            {
                builder.Defaults
                       .AllowSelf();

                builder.Scripts
                       .AllowSelf()
                       .Allow("https://ajax.aspnetcdn.com");

                builder.Styles
                       .AllowSelf()
                       .Allow("https://ajax.aspnetcdn.com");

                builder.Fonts
                       .AllowSelf()
                       .Allow("https://ajax.aspnetcdn.com");

                builder.Images
                       .AllowSelf()
                       .Allow("https://media-www-asp.azureedge.net/");
            });
            app.UseStaticFiles();

            app.UseIdentity();

            // Adds IdentityServer
            app.UseIdentityServer();

            // Add external authentication middleware below. To configure them please see https://go.microsoft.com/fwlink/?LinkID=532715
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
        private void InitializeDatabase(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            bool isTesting = env.IsEnvironment("Test") || env.IsDevelopment();

            var apiResources = Config.GetApiResources().ToList();
            var clients = Config.GetClients().ToList();
            var idResources = Config.GetIdentityResources().ToList();

            if (isTesting)
            {
                apiResources.Add(new ApiResource("test", "Test Resource"));
                clients.Add(new Client
                {
                    ClientId = "unit.test",
                    ClientName = "Unit Test",
                    ClientSecrets =
                    {
                        new Secret("test".Sha256())
                    },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "service.project.read",
                        "service.project.write",
                        "test"
                    }
                });
            }


            using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.Migrate();

                serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

                var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                context.Database.Migrate();

                if (!context.Clients.Any())
                {
                    foreach (var client in clients)
                    {
                        context.Clients.Add(client.ToEntity());
                    }

                    context.SaveChanges();
                }

                if (!context.IdentityResources.Any())
                {
                    foreach (var resource in idResources)
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.ApiResources.Any())
                {
                    foreach (var resource in apiResources)
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
            }
        }
    }
}
