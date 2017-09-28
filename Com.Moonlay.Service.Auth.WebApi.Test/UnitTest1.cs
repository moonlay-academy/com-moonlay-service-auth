using IdentityModel.Client;
using System;
using Xunit;

namespace Com.Moonlay.Service.Auth.WebApi.Test
{
    public class UnitTest1
    {
        [Fact]
        public void Test1()
        {
            var disco = DiscoveryClient.GetAsync("http://127.0.0.1:5000").Result;
            var tokenClient = new TokenClient(disco.TokenEndpoint, "unit.test", "test");
            var tokenResponse = tokenClient.RequestClientCredentialsAsync("service.project.read").Result;
            Assert.False(tokenResponse.IsError);
        }
    }
}
