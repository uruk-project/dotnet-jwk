﻿// Copyright (c) 2021 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    internal sealed class EncryptCommand : Command
    {
        public EncryptCommand()
            : base(name: "encrypt", description: "Encrypts a JWK")
        {
            Handler = CommandHandler.Create(typeof(EncryptCommandHandler).GetMethod(nameof(ICommandHandler.InvokeAsync), new[] { typeof(InvocationContext) })!);
        }

        internal static Command Create()
        {
            var command = new EncryptCommand()
                .OptionalKeyValue("The key to encrypt")
                .OptionalInputPath("The plain key input path. Use this option when the key is stored into a file.")
                .OptionalPrivateKeyOutputPath()
                .RequiredEncryptionPassword()
                .Force()
                .Verbose();

            return command;
        }

        internal class EncryptCommandHandler : CryptKeyCommand
        {
            public EncryptCommandHandler(string? key, string password, uint? iterationCount, uint? saltSize, FileInfo? inputPath, FileInfo? outputPath, bool force, IStore store)
                : base(key, password, iterationCount, saltSize, inputPath, outputPath, force, store)
            {
            }

            public override Task<int> InvokeAsync(InvocationContext context)
                => base.InvokeAsync(context);

            public override string Transform(IConsole console, string data)
            {
                var alg = KeyManagementAlgorithm.Pbes2HS256A128KW;
                var enc = EncryptionAlgorithm.A128CbcHS256;

                console.Verbose($@"Encrypting the JWK...
Algorithm: {alg}
Encryption algorithm: {enc}
Password derivation iteration count: {_iterationCount}
Password derivation salt size: {_saltSize} bits");
                var encryptionKey = PasswordBasedJwk.FromPassphrase(_password, iterationCount: _iterationCount, saltSizeInBytes: _saltSize);
                var writer = new JwtWriter();
                var descriptor = new PlaintextJweDescriptor(encryptionKey, KeyManagementAlgorithm.Pbes2HS256A128KW, EncryptionAlgorithm.A128CbcHS256)
                {
                    Payload = data
                };
                var result = writer.WriteTokenString(descriptor);
                console.Verbose("JWK encrypted.");
                return result;
            }
        }
    }   
}
