using System;
using System.IO;
using Fail2Ban4Win.Injection;
using Xunit;

namespace Fail2Ban4Win.Tests.Config;

public sealed class IniConfigurationTest {
    [Fact]
    public void IniBindsSafetyDefaultsAndSelectors() {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".ini");
        try {
            File.WriteAllText(path, "isDryRun=true\nmaxAllowedFailures=4\nbanSubnetBits=0\nneverBanReservedSubnets=true\n[eventLogSelectors:0]\nfriendlyName=Test\nlogName=Application\neventId=123\nipAddressEventDataName=Address\n");
            var configuration = ConfigurationModule.LoadConfiguration(path);
            Assert.True(configuration.isDryRun);
            Assert.Equal(4, configuration.maxAllowedFailures);
            Assert.Equal<byte?>((byte)0, configuration.banSubnetBits);
            Assert.Single(configuration.eventLogSelectors);
        } finally { File.Delete(path); }
    }
}
