using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Com.Moonlay.Service.Auth.WebApi.Middlewares.CSP
{
    public class CSPOptionsBuilder
    {
        private readonly CSPOptions options = new CSPOptions();

        internal CSPOptionsBuilder() { }

        public CSPDirectiveBuilder Defaults { get; set; } = new CSPDirectiveBuilder();
        public CSPDirectiveBuilder Scripts { get; set; } = new CSPDirectiveBuilder();
        public CSPDirectiveBuilder Styles { get; set; } = new CSPDirectiveBuilder();
        public CSPDirectiveBuilder Images { get; set; } = new CSPDirectiveBuilder();
        public CSPDirectiveBuilder Fonts { get; set; } = new CSPDirectiveBuilder();
        public CSPDirectiveBuilder Media { get; set; } = new CSPDirectiveBuilder();

        internal CSPOptions Build()
        {
            this.options.Defaults = this.Defaults.Sources;
            this.options.Scripts = this.Scripts.Sources;
            this.options.Styles = this.Styles.Sources;
            this.options.Images = this.Images.Sources;
            this.options.Fonts = this.Fonts.Sources;
            this.options.Media = this.Media.Sources;
            return this.options;
        }
    }
    public sealed class CSPDirectiveBuilder
    {
        internal CSPDirectiveBuilder() { }

        internal List<string> Sources { get; set; } = new List<string>();

        public CSPDirectiveBuilder AllowSelf() => Allow("'self'");
        public CSPDirectiveBuilder AllowNone() => Allow("none");
        public CSPDirectiveBuilder AllowAny() => Allow("*");

        public CSPDirectiveBuilder Allow(string source)
        {
            this.Sources.Add(source);
            return this;
        }
    }
}
