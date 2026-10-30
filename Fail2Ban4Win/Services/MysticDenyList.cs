// Added for the geosone fork: exact-address Mystic ban/unban action, 2026-10-30. Apache-2.0.
#nullable enable
using System.IO;
using System.Text;
using System.Threading;

namespace Fail2Ban4Win.Services;

/// <summary>Persistent, idempotent action queue. A locked Mystic file is retried, never unlocked forcibly.</summary>
public sealed class MysticDenyList: IDisposable {
    private readonly string path,state;
    private readonly bool allowUnban;
    private readonly Dictionary<string,bool> pending=new(StringComparer.OrdinalIgnoreCase);
    private readonly object sync=new();
    private readonly Timer timer;
    private static readonly Logger Log=LogManager.GetCurrentClassLogger();
    public MysticDenyList(string path,string state,bool allowUnban=true) {
        this.allowUnban=allowUnban;
        this.path=path;this.state=state;
        if(File.Exists(state)) foreach(string line in File.ReadAllLines(state)) {
            if(line=="[Pending]" || string.IsNullOrWhiteSpace(line)) continue;
            string[] parts=line.Split('=');
            if(parts.Length!=2 || !MysticControlServer.TryAddress(parts[0],out IPAddress? ip) || (parts[1]!="ban" && parts[1]!="unban")) throw new InvalidDataException("Invalid Mystic denylist action state.");
            pending[ip!.ToString()]=parts[1]=="ban";
        }
        timer=new Timer(_=>Retry(),null,5000,5000);
    }
    public void Set(IPAddress ip,bool ban) { if(!ban && !allowUnban) return; lock(sync) { pending[ip.ToString()]=ban;Save();Retry(); } }
    public void Retry() {
        lock(sync) foreach(var operation in pending.ToArray()) {
            try { if(!operation.Value && !allowUnban){pending.Remove(operation.Key);Save();continue;} Update(path,IPAddress.Parse(operation.Key),operation.Value);pending.Remove(operation.Key);Save(); }
            catch(IOException e) { Log.Warn("Mystic denylist is busy/unavailable; queued action retained: {error}",e.Message); }
            catch(UnauthorizedAccessException e) { Log.Warn("Mystic denylist action needs filesystem permission; queued action retained: {error}",e.Message); }
        }
    }
    private void Save() {
        Directory.CreateDirectory(Path.GetDirectoryName(state)!);
        AtomicWrite(state,Encoding.UTF8.GetBytes("[Pending]\n"+string.Join("\n",pending.Select(p=>p.Key+"="+(p.Value?"ban":"unban")))+"\n"));
    }
    public static void Update(string path,IPAddress ip,bool ban) {
        byte[] before=File.Exists(path)?File.ReadAllBytes(path):Array.Empty<byte>();
        Encoding encoding=Encoding.GetEncoding(28591);string text=encoding.GetString(before);
        string newline=text.Length==0?Environment.NewLine:(text.Contains("\r\n")?"\r\n":"\n");
        string[] lines=text.Split(new[]{"\r\n","\n"},StringSplitOptions.None);
        bool Matches(string line)=>IPAddress.TryParse(line.Trim(),out IPAddress? existing) && (existing.IsIPv4MappedToIPv6?existing.MapToIPv4():existing).Equals(ip);
        if(ban && lines.Any(Matches)) return;
        if(!ban && !lines.Any(Matches)) return;
        string result;
        if(ban) result=text+(text.Length>0 && !text.EndsWith("\n")?newline:"")+ip+newline;
        else result=string.Join(newline,lines.Where(line=>!Matches(line)));
        // Detect competing edits before replacing; a backup is made by the atomic filesystem operation.
        if(File.Exists(path) && !File.ReadAllBytes(path).SequenceEqual(before)) throw new IOException("Concurrent denylist edit; retry required.");
        AtomicWrite(path,encoding.GetBytes(result));
    }
    private static void AtomicWrite(string path,byte[] bytes) {
        string temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        File.WriteAllBytes(temporary,bytes);
        try {if(File.Exists(path))File.Replace(temporary,path,path+".fail2ban4win.bak");else File.Move(temporary,path);}
        finally {if(File.Exists(temporary))File.Delete(temporary);}
    }
    public void Dispose() { timer.Dispose(); }
}
