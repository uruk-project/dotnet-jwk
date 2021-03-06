﻿// Copyright (c) 2021 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tools.Jwk.Tests
{
    public class FileStoreTests
    {
        [Fact]
        public async Task Read_FileExists_ReturnsData()
        {
            FileStore store = new FileStore();
            var filename = Path.GetTempFileName();
            File.WriteAllText(filename, "Hello world");
            try
            {
                var data = await store.Read(filename);
                Assert.Equal("Hello world", data);
            }
            finally
            {
                File.Delete(filename);
            }
        }

        [Fact]
        public void Read_FileNotExists_ThrowFileNotFoundException()
        {
            FileStore store = new FileStore();
            var filename = Path.GetTempFileName();
            File.Delete(filename);
            Assert.ThrowsAsync<InvalidOperationException>(() => store.Read(filename));
        }

        [Fact]
        public void Write_FileNotExists_DataWritten()
        {
            FileStore store = new FileStore();
            var filename = Path.GetTempFileName();
            File.Delete(filename);
            try
            {
                store.Write(filename, "Hello world", false);
                Assert.Equal("Hello world", File.ReadAllText(filename));
            }
            finally
            {
                File.Delete(filename);
            }
        }

        [Fact]
        public void Write_FileExists_ThrowFileNotFoundException()
        {
            FileStore store = new FileStore();
            var filename = Path.GetTempFileName();
            try
            {
                Assert.ThrowsAsync<InvalidOperationException>(() => store.Write(filename, "Hello world", false));
            }
            finally
            {
                File.Delete(filename);
            }
        }

        [Fact]
        public void Write_FileExists_Force_DataWritten()
        {
            FileStore store = new FileStore();
            var filename = Path.GetTempFileName();
            try
            {
                store.Write(filename, "Hello world", true);
                Assert.Equal("Hello world", File.ReadAllText(filename));
            }
            finally
            {
                File.Delete(filename);
            }
        }
    }
}
