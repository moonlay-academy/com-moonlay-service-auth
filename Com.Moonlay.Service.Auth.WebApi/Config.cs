using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Hosting;

namespace Com.Moonlay.Service.Auth.WebApi
{
    public class Config
    {
        static IApplicationBuilder app;
        static IHostingEnvironment env;
        static ILoggerFactory loggerFactory;

        public static void Init(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            Config.app = app;
            Config.env = env;
            Config.loggerFactory = loggerFactory;
        }
        // scopes define the API resources in your system
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            var apiResources = new List<ApiResource>
            {
                new ApiResource{
                    Name ="api.gateway",
                    ApiSecrets =  {
                        new Secret("secret".Sha256())
                    },
                    DisplayName = "Moonlay Azure API Management Gateway",
                    Description = "Moonlay Azure API Management Gateway",
                    Scopes=new List<Scope> {
                    new Scope("api.gateway")
                }},

                new ApiResource{
                    Name ="com.moonlay.service.project",
                    ApiSecrets =  {
                        new Secret("secret".Sha256())
                    },
                    DisplayName = "Moonlay Project  API Service",
                    Description = "Moonlay Project  API Service",
                    Scopes=new List<Scope> {
                    new Scope("service.project.read"),
                    new Scope("service.project.write")
                }},
            };

            if (env.IsEnvironment("Test"))
                apiResources.Add(new ApiResource("test", "Test Resource"));

            return apiResources;
        }

        // client want to access resources (aka scopes)
        public static IEnumerable<Client> GetClients()
        {
            List<Client> clients = new List<Client>
            {
                new Client
                {
                    ClientId = "api.gateway",
                    ClientName = "Moonlay Azure API Management Gateway",
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    AllowedGrantTypes = GrantTypes.ImplicitAndClientCredentials,
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "service.project.read",
                        "service.project.write"
                    },
                    RedirectUris ={
                        "https://api-management-dev.portal.azure-api.net/docs/services/59ba5edbd901221240eb42bb/console/openidconnect/authorizationcode/callback",
                        "https://api-management-dev.portal.azure-api.net/docs/services/59ba5edbd901221240eb42bb/console/openidconnect/implicit/callback",

                        "https://api-management-dev.portal.azure-api.net/docs/services/59ba7071d901221240eb42c0/console/oauth2/authorizationcode/callback",
                        "https://api-management-dev.portal.azure-api.net/docs/services/59ba7071d901221240eb42c0/console/oauth2/implicit/callback"
                    }
                },

                new Client
                {
                    ClientId = "postman",
                    ClientName = "Postman Rest App",
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },
                    AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "service.project.read",
                        "service.project.write"
                    },
                    RedirectUris ={
                        "https://getpostman.com/oauth2/callback"
                    }
                }
            };

            if (env.IsEnvironment("Test"))
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
            return clients;
        }
    }
}
