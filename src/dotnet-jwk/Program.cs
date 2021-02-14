// Copyright (c) 2021 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    public class Program
    {
        private static ParseResult? _parseResult;

        private static async Task<int> Main(string[] args)
        {
            var rootCommand = CreateCommand();
            Parser parser = BuildParser(rootCommand);

            _parseResult = parser.Parse(args);
            ConsoleExtensions.IsVerbose = _parseResult.HasOption("--verbose");

            return await parser.InvokeAsync(args);
        }

        internal static RootCommand CreateCommand()
        {
            return new RootCommand("Manages JSON Web Keys")
            {
                NewCommand.Create(),
                EncryptCommand.Create(),
                DecryptCommand.Create(),
                ConvertCommand.Create(),
                CheckCommand.Create()
            };
        }

        private static Parser BuildParser(RootCommand command)
        {
            var commandLineBuilder = new CommandLineBuilder(command);

            commandLineBuilder.UseMiddleware(ctx =>
            {
                ctx.BindingContext.AddService<IStore>(p => new FileStore());
            });

            return commandLineBuilder.UseDefaults().Build();
        }
    }
}
