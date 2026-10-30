// Added for the geosone fork: local Mystic IP Blocked hook, 2026-10-30. Apache-2.0.
#nullable enable
using Fail2Ban4Win.Config;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Fail2Ban4Win.Services;

public sealed class MysticControlServer: IDisposable {
    private readonly CancellationTokenSource stop = new();
    private readonly List<NamedPipeServerStream> pipes = new();
    private readonly BanManager manager;
    private readonly Configuration config;
    private Task? worker;
    private static readonly Logger Log = LogManager.GetCurrentClassLogger();
    public MysticControlServer(BanManager manager, Configuration config) { this.manager=manager; this.config=config; }
    public void Start() {
        if (!config.mysticHook.enabled) return;
        if (!System.Text.RegularExpressions.Regex.IsMatch(config.mysticHook.pipeName, @"^[A-Za-z0-9._-]{1,128}$")) throw new ArgumentException("Invalid Mystic pipe name.");
        if ((config.banSubnetBits ?? 0) != 0) throw new ArgumentException("Mystic hooks require individual IP bans (banSubnetBits=0).");
        PipeSecurity acl = new();
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null), PipeAccessRights.FullControl, AccessControlType.Deny));
        foreach (WellKnownSidType sid in new[] {WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})
            acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
        if (!string.IsNullOrWhiteSpace(config.mysticHook.allowedClientSid))
            acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(config.mysticHook.allowedClientSid),PipeAccessRights.ReadWrite,AccessControlType.Allow));
        // Create the protected endpoint before reporting successful service startup.
        NamedPipeServerStream pipe = new(config.mysticHook.pipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,256,256,acl);
        pipes.Add(pipe);
        worker=Task.Run(async () => {
            while (!stop.IsCancellationRequested) {
                try {
                    await pipe.WaitForConnectionAsync(stop.Token);
                    string? command = await ReadCommand(pipe);
                    string response = command is null ? "ERROR" : Dispatch(command);
                    byte[] reply=Encoding.ASCII.GetBytes(response+"\n");
                    await pipe.WriteAsync(reply,0,reply.Length,stop.Token);
                    await pipe.FlushAsync(stop.Token);
                } catch (Exception e) when (e is not OutOfMemoryException) {
                    if (!stop.IsCancellationRequested) Log.Error(e,"Mystic control request failed");
                } finally { if (pipe.IsConnected) pipe.Disconnect(); }
            }
        });
    }
    private async Task<string?> ReadCommand(NamedPipeServerStream pipe) {
        byte[] one=new byte[1]; StringBuilder command=new();
        Task deadline=Task.Delay(5000,stop.Token);
        while(command.Length<128){
            Task<int> read=pipe.ReadAsync(one,0,1,stop.Token);
            if(await Task.WhenAny(read,deadline)!=read) { pipe.Disconnect(); return null; }
            if(await read==0) return null;
            if(one[0]==10) return command.ToString();
            if(one[0]<32 || one[0]>126) return null;
            command.Append((char)one[0]);
        }
        return null;
    }
    public string Dispatch(string command) {
        string[] parts=command.Split(' ');
        if(parts.Length!=2 || (parts[0]!="ban" && parts[0]!="unban") || !TryAddress(parts[1],out IPAddress? address)) return "ERROR";
        if(config.isDryRun) return "DRYRUN";
        return (parts[0]=="ban" ? manager.BanAddress(address!) : manager.UnbanAddress(address!)) ? "OK" : "SKIPPED";
    }
    public static bool TryAddress(string text,out IPAddress? address) {
        address=null;
        if(!System.Text.RegularExpressions.Regex.IsMatch(text,@"^[0-9A-Fa-f:.]+$") || !IPAddress.TryParse(text,out address)) return false;
        if(address.IsIPv4MappedToIPv6) address=address.MapToIPv4();
        if(address.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork && !text.Contains(':') && address.ToString()!=text) return false;
        return !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any) && !address.IsIPv6Multicast;
    }
    public void Dispose() {
        stop.Cancel(); foreach(var pipe in pipes) pipe.Dispose();
        try { worker?.Wait(TimeSpan.FromSeconds(6)); } catch(AggregateException) { }
        stop.Dispose();
    }
}
