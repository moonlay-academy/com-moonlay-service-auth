using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Com.Moonlay.Service.Auth.WebApi.Middlewares.CSP
{
    public sealed class CSPMiddleware
    {
        private const string HEADER = "Content-Security-Policy";
        private readonly RequestDelegate next;
        private readonly CSPOptions options;

        public CSPMiddleware(
            RequestDelegate next, CSPOptions options)
        {
            this.next = next;
            this.options = options;
        }

        public async Task Invoke(HttpContext context)
        {
            context.Response.Headers.Add(HEADER, GetHeaderValue());
            await this.next(context);
        }

        private string GetHeaderValue()
        {
            var value = "";
            value += GetDirective("default-src", this.options.Defaults);
            value += GetDirective("script-src", this.options.Scripts);
            value += GetDirective("style-src", this.options.Styles);
            value += GetDirective("img-src", this.options.Images);
            value += GetDirective("font-src", this.options.Fonts);
            value += GetDirective("media-src", this.options.Media);
            return value;
        }

        private string GetDirective(string directive, List<string> sources)
            => sources.Count > 0 ? $"{directive} {string.Join(" ", sources)}; " : "";
    }
}
