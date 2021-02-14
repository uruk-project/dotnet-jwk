// Copyright (c) 2021 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    internal sealed class DecryptCommand : Command
    {
        private DecryptCommand()
            : base(name: "decrypt", description: "Decrypts a JWK")
        {
            Handler = CommandHandler.Create(typeof(DecryptCommandHandler).GetMethod(nameof(ICommandHandler.InvokeAsync), new[] { typeof(InvocationContext) })!);
        }

        internal static Command Create()
        {
            var command = new DecryptCommand()
                .OptionalKeyValue("The key to encrypt")
                .OptionalInputPath("The plain key input path. Use this option when the key is stored into a file.")
                .OptionalPrivateKeyOutputPath()
                .RequiredEncryptionPassword()
                .Force()
                .Verbose();

            return command;
        }

        internal class DecryptCommandHandler : CryptKeyCommand
        {
            public DecryptCommandHandler(string? key, string password, uint? iterationCount, uint? saltSize, FileInfo? inputPath, FileInfo? outputPath, bool force, IStore store)
                : base(key, password, iterationCount, saltSize, inputPath, outputPath, force, store)
            {
            }

            public override Task<int> InvokeAsync(InvocationContext context)
                => base.InvokeAsync(context);

            public override string Transform(IConsole console, string data)
            {
                console.Verbose($@"Decrypting the JWK...
Password derivation iteration count: {_iterationCount}
Password derivation salt size: {_saltSize} bits");
                var decryptionKey = PasswordBasedJwk.FromPassphrase(_password, _iterationCount, _saltSize);
                var policy = new TokenValidationPolicyBuilder().WithDecryptionKeys(decryptionKey).IgnoreNestedToken().AcceptUnsecureTokenByDefault().Build();
                Jwt? jwt = null;
                try
                {
                    if (!Jwt.TryParse(data, policy, out jwt))
                    {
                        throw new InvalidOperationException($"Failed to decrypt the key.\n{jwt.Error!.Status}\n{jwt.Error!.Message}");
                    }

                    console.Verbose("JWK decrypted.");
                    return jwt.Plaintext;
                }
                finally
                {
                    jwt?.Dispose();
                }
            }
        }
    }   
}
