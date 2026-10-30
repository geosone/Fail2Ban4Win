#nullable enable

using Fail2Ban4Win.Logging;
using Fail2Ban4Win.Config;
using Fail2Ban4Win.Services;
using LightInject;
using System.Reflection;
using System.ServiceProcess;

namespace Fail2Ban4Win.Entry;

public sealed partial class WindowsService: ServiceBase {

    private ServiceContainer? context;
    private Scope?            scope;
    private MysticControlServer? mysticControl;

    public WindowsService() {
        InitializeComponent();
        UnfuckedValueFormatter.register();
    }

    protected override void OnStart(string[] args) {
        context = new ServiceContainer();
        context.RegisterAssembly(Assembly.GetCallingAssembly());
        scope = context.BeginScope();

        var manager=scope.GetInstance<BanManager>();
        mysticControl=new MysticControlServer(manager,scope.GetInstance<Configuration>());
        mysticControl.Start();
    }

    protected override void OnStop() {
        mysticControl?.Dispose();
        scope?.Dispose();
        context?.Dispose();
    }

    public void stopManually() => OnStop();

    public void startManually(string[] args) => OnStart(args);

}