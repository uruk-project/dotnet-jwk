// Copyright (c) 2021 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    internal class CheckCommand : Command
    {
        private CheckCommand() 
            : base(name: "check", description: "Checks the validity of a JWK")
        {
            Handler = CommandHandler.Create(typeof(CheckCommandHandler).GetMethod(nameof(ICommandHandler.InvokeAsync))!);
        }
        
        internal static Command Create()
        {
            var command = new CheckCommand()
                .RequiredInputPath()
                .Verbose();

            return command;
        }

        internal class CheckCommandHandler : ICommandHandler
        {
            private readonly FileInfo _inputPath;
            private readonly IStore _store;

            public CheckCommandHandler(FileInfo inputPath, IStore store)
            {
                _inputPath = inputPath;
                _store = store;
            }

            public Task<int> InvokeAsync(InvocationContext context)
                => InvokeAsync(context.Console);

            internal async Task<int> InvokeAsync(IConsole console)
            {
                console.Verbose($"Reading JWK from {_inputPath} file...");
                var value = await _store.Read(_inputPath.FullName);
                console.Verbose("JWK successfully read.");

                console.Verbose("Validating the JWK...");
                try
                {
                    JsonWebToken.Jwk.Check(value);
                    console.Write("JWK Validated.");
                }
                catch (JwkCheckException e)
                {
                    console.Error("Error:");
                    if (e.InnerException is JsonException jsonException)
                    {
                        string message = "Malformed JSON object. ";
                        if (jsonException.Path != null)
                        {
                            message += $"Path: {jsonException.Path}. ";
                        }

                        if (jsonException.LineNumber.HasValue)
                        {
                            message += $"Line: {jsonException.LineNumber}. ";
                        }

                        if (jsonException.BytePositionInLine.HasValue)
                        {
                            message += $"Position: {jsonException.BytePositionInLine}. ";
                        }

                        console.Error(message);
                        console.Error(jsonException.Message);
                    }
                    else
                    {
                        console.Error(e.Message);
                    }
                }

                return 0;
            }
        }
    }
}
