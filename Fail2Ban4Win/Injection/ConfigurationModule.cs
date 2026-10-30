#nullable enable

using Fail2Ban4Win.Config;
using LightInject;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace Fail2Ban4Win.Injection;

public sealed class ConfigurationModule: ICompositionRoot {

    internal const string FILENAME = "configuration.json";

    // MSI-managed settings live outside Program Files. Legacy JSON remains supported.
    public static Configuration LoadConfiguration() {
        string iniPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Fail2Ban4Win", "configuration.ini");
        return LoadConfiguration(iniPath);
    }

    public static Configuration LoadConfiguration(string iniPath) {
        IConfigurationBuilder builder = new ConfigurationBuilder();
        if (File.Exists(iniPath)) {
            builder.AddIniFile(iniPath, optional: false, reloadOnChange: false);
        } else {
            builder.AddJsonFile(FILENAME);
        }
        return builder.Build().Get<Configuration>() ?? throw new InvalidOperationException("Missing Fail2Ban4Win configuration.");
    }

    public void Compose(IServiceRegistry serviceRegistry) {
        serviceRegistry.Register(_ => LoadConfiguration(), new PerScopeLifetime());

        IPNetworkDeserializer.register();
        RegexDeserializer.register();
    }

}