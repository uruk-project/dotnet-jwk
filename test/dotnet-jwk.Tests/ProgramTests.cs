// Copyright (c) 2021 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.CommandLine;
using System.IO;
using Xunit;

namespace JsonWebToken.Tools.Jwk.Tests
{
    public class ProgramTests
    {
        [Fact]
        public void CommandLine_New_Oct()
        {
            var sut = Program.CreateCommand();
            var result = sut.Parse(new[] {
                "new", "oct",
                "--length", "128",
                "--alg", "HS256",
                "--use", "sig",
                "--key-ops", "sign", "verify",
                "--password", "P@ssw0rd",
                "--iteration-count", "10000",
                "--salt-size", "256",
                "--no-kid",
                "--kid", "Billy",
                "--output-path", "./key.json",
                "--force",
                "--verbose"
            });

            Assert.Equal(0, result.Errors.Count);
            Assert.Equal(0, result.UnmatchedTokens.Count);
            Assert.Equal(0, result.UnparsedTokens.Count);
            Assert.Equal(128, result.ValueForOption<int>("--length"));
            Assert.Equal("HS256", result.ValueForOption<string>("--alg"));
            Assert.Equal("sig", result.ValueForOption<string>("--use"));
            Assert.Collection(result.ValueForOption<IEnumerable<string>>("--key-ops"),
               i0 => Assert.Equal("sign", i0),
               i1 => Assert.Equal("verify", i1));
            Assert.Equal("./key.json", result.ValueForOption<FileInfo>("--output-path")?.ToString());
            Assert.Equal("P@ssw0rd", result.ValueForOption<string>("--password")); ;
            Assert.Equal(10000, result.ValueForOption<int>("--iteration-count"));
            Assert.Equal(256, result.ValueForOption<int>("--salt-size"));
            Assert.Equal("Billy", result.ValueForOption<string>("--kid"));
            Assert.True(result.ValueForOption<bool>("--no-kid"));
            Assert.True(result.ValueForOption<bool>("--force"));
            Assert.True(result.ValueForOption<bool>("--verbose"));
        }

        [Fact]
        public void CommandLine_New_Rsa()
        {
            var sut = Program.CreateCommand();
            var result = sut.Parse(new[] {
                "new", "RSA",
                "--length", "1024",
                "--alg", "PS256",
                "--use", "sig",
                "--key-ops", "sign", "verify",
                "--password", "P@ssw0rd",
                "--iteration-count", "10000",
                "--salt-size", "256",
                "--no-kid",
                "--kid", "Billy",
                "--output-path", "./key.json",
                "--force",
                "--verbose"
            });

            Assert.Equal(0, result.Errors.Count);
            Assert.Equal(0, result.UnmatchedTokens.Count);
            Assert.Equal(0, result.UnparsedTokens.Count);
            Assert.Equal(1024, result.ValueForOption<int>("--length"));
            Assert.Equal("PS256", result.ValueForOption<string>("--alg"));
            Assert.Equal("sig", result.ValueForOption<string>("--use"));
            Assert.Collection(result.ValueForOption<IEnumerable<string>>("--key-ops"),
               i0 => Assert.Equal("sign", i0),
               i1 => Assert.Equal("verify", i1));
            Assert.Equal("./key.json", result.ValueForOption<FileInfo>("--output-path")?.ToString());
            Assert.Equal("P@ssw0rd", result.ValueForOption<string>("--password")); ;
            Assert.Equal(10000, result.ValueForOption<int>("--iteration-count"));
            Assert.Equal(256, result.ValueForOption<int>("--salt-size"));
            Assert.Equal("Billy", result.ValueForOption<string>("--kid"));
            Assert.True(result.ValueForOption<bool>("--no-kid"));
            Assert.True(result.ValueForOption<bool>("--force"));
            Assert.True(result.ValueForOption<bool>("--verbose"));
        }

        [Fact]
        public void CommandLine_New_EC()
        {
            var sut = Program.CreateCommand();
            var result = sut.Parse(new[] {
                "new", "EC",
                "--curve", "P-256",
                "--alg", "ES256",
                "--use", "sig",
                "--key-ops", "sign", "verify",
                "--password", "P@ssw0rd",
                "--iteration-count", "10000",
                "--salt-size", "256",
                "--no-kid",
                "--kid", "Billy",
                "--output-path", "./key.json",
                "--force",
                "--verbose"
            });

            Assert.Equal(0, result.Errors.Count);
            Assert.Equal(0, result.UnmatchedTokens.Count);
            Assert.Equal(0, result.UnparsedTokens.Count);
            Assert.Equal("P-256", result.ValueForOption<string>("--curve"));
            Assert.Equal("ES256", result.ValueForOption<string>("--alg"));
            Assert.Equal("sig", result.ValueForOption<string>("--use"));
            Assert.Collection(result.ValueForOption<IEnumerable<string>>("--key-ops"),
               i0 => Assert.Equal("sign", i0),
               i1 => Assert.Equal("verify", i1));
            Assert.Equal("./key.json", result.ValueForOption<FileInfo>("--output-path")?.ToString());
            Assert.Equal("P@ssw0rd", result.ValueForOption<string>("--password")); ;
            Assert.Equal(10000, result.ValueForOption<int>("--iteration-count"));
            Assert.Equal(256, result.ValueForOption<int>("--salt-size"));
            Assert.Equal("Billy", result.ValueForOption<string>("--kid"));
            Assert.True(result.ValueForOption<bool>("--no-kid"));
            Assert.True(result.ValueForOption<bool>("--force"));
            Assert.True(result.ValueForOption<bool>("--verbose"));
        }
        
        [Fact]
        public void CommandLine_Encrypt()
        {
            var sut = Program.CreateCommand();
            var result = sut.Parse(new[] {
                "encrypt",
                "--input-path", "./key.json",
                "--output-path", "./encrypted.json",
                "--password", "P@ssw0rd",
                "--iteration-count", "10000",
                "--salt-size", "256",
                "--force",
                "--verbose"
            });

            Assert.Equal(0, result.Errors.Count);
            Assert.Equal(0, result.UnmatchedTokens.Count);
            Assert.Equal(0, result.UnparsedTokens.Count);
            Assert.Equal("./key.json", result.ValueForOption<FileInfo>("--input-path")?.ToString());
            Assert.Equal("./encrypted.json", result.ValueForOption<FileInfo>("--output-path")?.ToString());
            Assert.Equal("P@ssw0rd", result.ValueForOption<string>("--password")); ;
            Assert.Equal(10000, result.ValueForOption<int>("--iteration-count"));
            Assert.Equal(256, result.ValueForOption<int>("--salt-size"));
            Assert.True(result.ValueForOption<bool>("--force"));
            Assert.True(result.ValueForOption<bool>("--verbose"));
        }

        [Fact]
        public void CommandLine_Decrypt()
        {
            var sut = Program.CreateCommand();
            var result = sut.Parse(new[] {
                "decrypt",
                "--input-path", "./encrypted.json",
                "--output-path", "./key.json",
                "--password", "P@ssw0rd",
                "--iteration-count", "10000",
                "--salt-size", "256",
                "--force",
                "--verbose"
            });

            Assert.Equal(0, result.Errors.Count);
            Assert.Equal(0, result.UnmatchedTokens.Count);
            Assert.Equal(0, result.UnparsedTokens.Count);
            Assert.Equal("./encrypted.json", result.ValueForOption<FileInfo>("--input-path")?.ToString());
            Assert.Equal("./key.json", result.ValueForOption<FileInfo>("--output-path")?.ToString());
            Assert.Equal("P@ssw0rd", result.ValueForOption<FileInfo>("--password")?.ToString());
            Assert.Equal(10000, result.ValueForOption<int>("--iteration-count"));
            Assert.Equal(256, result.ValueForOption<int>("--salt-size"));
            Assert.True(result.ValueForOption<bool>("--force"));
            Assert.True(result.ValueForOption<bool>("--verbose"));
        }

        [Fact]
        public void CommandLine_ConvertPem()
        {
            var sut = Program.CreateCommand();
            var result = sut.Parse(new[] {
                "convert", "PEM",
                "--input-path", "./key.pem",
                "--output-path", "./key.json",
                "--public-output-path", "./public_key.json",
                "--password", "P@ssw0rd",
                "--iteration-count", "10000",
                "--salt-size", "256",
                "--force",
                "--verbose"
            });

            Assert.Equal(0, result.Errors.Count);
            Assert.Equal(0, result.UnmatchedTokens.Count);
            Assert.Equal(0, result.UnparsedTokens.Count);
            Assert.Equal("./key.pem", result.ValueForOption<FileInfo>("--input-path")?.ToString());
            Assert.Equal("./key.json", result.ValueForOption<FileInfo>("--output-path")?.ToString());
            Assert.Equal("./public_key.json", result.ValueForOption<FileInfo>("--public-output-path")?.ToString());
            Assert.Equal("P@ssw0rd", result.ValueForOption<string>("--password")); ;
            Assert.Equal(10000, result.ValueForOption<int>("--iteration-count"));
            Assert.Equal(256, result.ValueForOption<int>("--salt-size"));
            Assert.True(result.ValueForOption<bool>("--force"));
            Assert.True(result.ValueForOption<bool>("--verbose"));
        }

        [Fact]
        public void CommandLine_ConvertX509()
        {
            var sut = Program.CreateCommand();
            var result = sut.Parse(new[] {
                "convert", "X509",
                "--input-path", "./key.cer",
                "--output-path", "./key.json",
                "--public-output-path", "./public_key.json",
                "--certificate-password", "P@ssw0rdX",
                "--password", "P@ssw0rd",
                "--iteration-count", "10000",
                "--salt-size", "256",
                "--force",
                "--verbose"
            });

            Assert.Equal(0, result.Errors.Count);
            Assert.Equal(0, result.UnmatchedTokens.Count);
            Assert.Equal(0, result.UnparsedTokens.Count);
            Assert.Equal("./key.cer", result.ValueForOption<FileInfo>("--input-path")?.ToString());
            Assert.Equal("./key.json", result.ValueForOption<FileInfo>("--output-path")?.ToString());
            Assert.Equal("./public_key.json", result.ValueForOption<FileInfo>("--public-output-path")?.ToString());
            Assert.Equal("P@ssw0rd", result.ValueForOption<string>("--password"));
            Assert.Equal("P@ssw0rdX", result.ValueForOption<string>("--certificate-password")); ;
            Assert.Equal(10000, result.ValueForOption<int>("--iteration-count"));
            Assert.Equal(256, result.ValueForOption<int>("--salt-size"));
            Assert.True(result.ValueForOption<bool>("--force"));
            Assert.True(result.ValueForOption<bool>("--verbose"));
        }
    }
}
