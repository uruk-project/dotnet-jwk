// Copyright (c) 2021 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    public interface IStore
    {
        Task<string> Read(string inputPath);
        Task Write(string outputPath, string key, bool force);
        Task<X509Certificate2> LoadX509(string inputPath, string? password);
    }
}
