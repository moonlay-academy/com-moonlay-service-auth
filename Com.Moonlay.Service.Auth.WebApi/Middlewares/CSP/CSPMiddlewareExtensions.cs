using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Com.Moonlay.Service.Auth.WebApi.Middlewares.CSP
{
    public static class CSPMiddlewareExtensions
    {
        public static IApplicationBuilder UseCsp(
            this IApplicationBuilder app, Action<CSPOptionsBuilder> builder)
        {
            var newBuilder = new CSPOptionsBuilder();
            builder(newBuilder);

            var options = newBuilder.Build();
            return app.UseMiddleware<CSPMiddleware>(options);
        }
    }
}
