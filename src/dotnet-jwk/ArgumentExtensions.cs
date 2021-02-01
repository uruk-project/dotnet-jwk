// Copyright (c) 2021 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.CommandLine;
using System.IO;
using System.Linq;

namespace JsonWebToken.Tools.Jwk
{
    internal static class ArgumentExtensions
    {
        internal static Argument<FileInfo> DoesNotExist<TArgument>(this Argument<FileInfo> argument)
        {
            argument.AddValidator(
               a =>
                   a.Tokens
                    .Select(t => t.Value)
                    .Where(filePath => !File.Exists(filePath))
                    .Select(FileAlreadyExist)
                    .FirstOrDefault());

            return argument;
        }

        private static string FileAlreadyExist(string filename)
            => $"File {filename} already exist. Use option --force for overwirting the existing file.";
    }
}
