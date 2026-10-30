using System;
using System.IO;
using System.Net;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Fail2Ban4Win.Config;
using Fail2Ban4Win.Services;
using FakeItEasy;
using Xunit;

namespace Tests.Services;
public sealed class MysticHookTest {
    [Fact]
    public async Task PipeReplySurvivesDelayedClientReadAndReconnect(){
        string name="MysticHookTest-"+Guid.NewGuid().ToString("N");
        var config=new Configuration {isDryRun=true};
        config.mysticHook.enabled=true;config.mysticHook.pipeName=name;
        config.mysticHook.allowedClientSid=WindowsIdentity.GetCurrent().User!.Value;
        using var server=new MysticControlServer(A.Fake<BanManager>(),config);server.Start();
        for(int i=0;i<3;i++){
            using var client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous);
            client.Connect(5000);
            byte[] request=Encoding.ASCII.GetBytes("status\n");await client.WriteAsync(request,0,request.Length);
            await Task.Delay(75);
            StringBuilder reply=new();byte[] one=new byte[1];
            while(true){
                Task<int> read=client.ReadAsync(one,0,1);
                Assert.Same(read,await Task.WhenAny(read,Task.Delay(5000)));
                Assert.Equal(1,await read);
                if(one[0]==10)break;
                reply.Append((char)one[0]);Assert.True(reply.Length<128);
            }
            Assert.Equal("DRYRUN MYSTIC-HOOK-1",reply.ToString());
            byte[] ack=Encoding.ASCII.GetBytes("ACK\n");await client.WriteAsync(ack,0,ack.Length);
        }
    }
    [Theory]
    [InlineData("1.2.3.4",true)]
    [InlineData("2001:db8::1",true)]
    [InlineData("1.2",false)]
    [InlineData("010.0.0.1",false)]
    [InlineData("1.2.3.4 & calc",false)]
    [InlineData("::",false)]
    public void LiteralAddressOnly(string value,bool valid)=>Assert.Equal(valid,MysticControlServer.TryAddress(value,out _));
    [Fact]
    public void DryRunDoesNotInvokeManager(){
        var manager=A.Fake<BanManager>();using var server=new MysticControlServer(manager,new Configuration {isDryRun=true});
        Assert.Equal("DRYRUN",server.Dispatch("ban 1.2.3.4"));
        A.CallTo(()=>manager.BanAddress(A<IPAddress>._)).MustNotHaveHappened();
    }
    [Fact]
    public void RejectMalformedCommands(){
        var manager=A.Fake<BanManager>();using var server=new MysticControlServer(manager,new Configuration());
        Assert.Equal("ERROR",server.Dispatch("ban 1.2.3.4 extra"));
        Assert.Equal("ERROR",server.Dispatch("execute 1.2.3.4"));
    }
    [Fact]
    public void BanUnbanDispatches(){
        var manager=A.Fake<BanManager>();A.CallTo(()=>manager.BanAddress(A<IPAddress>._)).Returns(true);A.CallTo(()=>manager.UnbanAddress(A<IPAddress>._)).Returns(true);
        using var server=new MysticControlServer(manager,new Configuration());
        Assert.Equal("OK",server.Dispatch("ban 1.2.3.4"));Assert.Equal("OK",server.Dispatch("unban 1.2.3.4"));
    }
    [Fact]
    public void DenylistPreservesUnrelatedAddressesAndBacksUp(){
        string dir=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString());Directory.CreateDirectory(dir);string path=Path.Combine(dir,"denylist.txt");
        try{
            File.WriteAllText(path,"# manual\r\n11.2.3.4\r\n1.2.3.4\r\n");
            MysticDenyList.Update(path,IPAddress.Parse("1.2.3.4"),false);
            Assert.Equal("# manual\r\n11.2.3.4\r\n",File.ReadAllText(path));Assert.True(File.Exists(path+".fail2ban4win.bak"));
            MysticDenyList.Update(path,IPAddress.Parse("1.2.3.4"),true);
            MysticDenyList.Update(path,IPAddress.Parse("1.2.3.4"),true);
            Assert.Equal("# manual\r\n11.2.3.4\r\n1.2.3.4\r\n",File.ReadAllText(path));
        } finally{Directory.Delete(dir,true);}
    }
    [Fact]
    public void LockedDenylistQueuesAndRecoversAfterRestart(){
        string dir=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString());Directory.CreateDirectory(dir);
        string path=Path.Combine(dir,"denylist.txt"),state=Path.Combine(dir,"pending.ini");File.WriteAllText(path,"# manual\r\n");
        try{
            using(var locked=File.Open(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
            using(var action=new MysticDenyList(path,state)){action.Set(IPAddress.Parse("192.0.2.5"),true);Assert.Contains("192.0.2.5=ban",File.ReadAllText(state));}
            using(var action=new MysticDenyList(path,state)){action.Retry();}
            Assert.Contains("192.0.2.5",File.ReadAllText(path));
            Assert.DoesNotContain("192.0.2.5=ban",File.ReadAllText(state));
        }finally{Directory.Delete(dir,true);}
    }
    [Fact]
    public void UnbanInMysticFalsePreservesDenylist(){
        string dir=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString());Directory.CreateDirectory(dir);string path=Path.Combine(dir,"denylist.txt");
        try{
            File.WriteAllText(path,"192.0.2.5\n");
            using(var action=new MysticDenyList(path,Path.Combine(dir,"pending.ini"),false)){action.Set(IPAddress.Parse("192.0.2.5"),false);action.Retry();}
            Assert.Equal("192.0.2.5\n",File.ReadAllText(path));
        }finally{Directory.Delete(dir,true);}
    }
}
