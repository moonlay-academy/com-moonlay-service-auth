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
            var discoClient = new DiscoveryClient("http://127.0.0.1:5000/"); //TOCHECK: is trailing / required?
            discoClient.Policy.RequireHttps = true;
            var disco = discoClient.GetAsync().Result;
            Assert.Null(disco.Error);
            Assert.True(disco.Error == null, disco.Error);
            Console.WriteLine(disco.Error);
            //var disco = DiscoveryClient.GetAsync("http://127.0.0.1:5000").Result;

            var tokenClient = new TokenClient(disco.TokenEndpoint, "unit.test", "test");
            var tokenResponse = tokenClient.RequestClientCredentialsAsync("service.project.read").Result;
            Assert.False(tokenResponse.IsError);
        }
    }
}
