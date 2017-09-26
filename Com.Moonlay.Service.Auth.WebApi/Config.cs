using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4;

namespace Com.Moonlay.Service.Auth.WebApi
{
    public class Config
    { // scopes define the API resources in your system
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
            return new List<ApiResource>
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
        }

        // client want to access resources (aka scopes)
        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "api.gateway",
                    ClientName = "JET Azure API Management Gateway",
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
        }
    }
}
