using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;
namespace SecureKon {
public class DnsConfig { public string Name{get;set;} public string Url{get;set;} public string[] IPv4{get;set;} public string[] IPv6{get;set;} }
public class Request {public string Id{get;set;} public string Action{get;set;} public DnsConfig Config{get;set;}}
public class Result {public string Id{get;set;} public string State{get;set;} public string Detail{get;set;} public string Timestamp{get;set;}}
public class InstallContext {public string Language{get;set;} public string Sid{get;set;} public string Programs{get;set;} public string Startup{get;set;} public string Desktop{get;set;} public int ParentPid{get;set;} }
public static class Core {
 public static string Install=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"SecureKon");
 public static string Data=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"SecureKon");
 public static string Exe {get{return Path.Combine(Install,"SecureKon.exe");}}
 public static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=32768};}
 public static T Read<T>(string path){return Json().Deserialize<T>(File.ReadAllText(path,Encoding.UTF8));}
 public static void Write(string path,object value){string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";File.WriteAllText(temp,Json().Serialize(value),new UTF8Encoding(false));if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);}
 public static DnsConfig[] Presets={
 new DnsConfig{Name="AdGuard",Url="https://dns.adguard-dns.com/dns-query",IPv4=new[]{"94.140.14.14","94.140.15.15"},IPv6=new[]{"2a10:50c0::ad1:ff","2a10:50c0::ad2:ff"}},
 new DnsConfig{Name="Google",Url="https://dns.google/dns-query",IPv4=new[]{"8.8.8.8","8.8.4.4"},IPv6=new[]{"2001:4860:4860::8888","2001:4860:4860::8844"}},
 new DnsConfig{Name="Cloudflare",Url="https://cloudflare-dns.com/dns-query",IPv4=new[]{"1.1.1.1","1.0.0.1"},IPv6=new[]{"2606:4700:4700::1111","2606:4700:4700::1001"}}
 };
 public static void Validate(DnsConfig c){Uri u;if(c==null||String.IsNullOrWhiteSpace(c.Url)||c.Url.Length>2048||!Uri.TryCreate(c.Url,UriKind.Absolute,out u)||u.Scheme!="https"||u.Host.Length==0||u.UserInfo.Length>0||u.Fragment.Length>0||c.Url.Any(Char.IsWhiteSpace))throw new Exception(L.T("Geçerli bir HTTPS DNS adresi girin.")); ValidateIPs(c.IPv4,AddressFamily.InterNetwork);ValidateIPs(c.IPv6,AddressFamily.InterNetworkV6);}
 static void ValidateIPs(string[] a,AddressFamily f){if(a==null||a.Length<1||a.Length>2)throw new Exception(L.T("IPv4 ve IPv6 için en az birer DNS adresi gerekli."));foreach(string s in a){IPAddress ip;if(!IPAddress.TryParse(s,out ip)||ip.AddressFamily!=f||IPAddress.IsLoopback(ip)||ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any))throw new Exception(L.T("Geçersiz DNS adresi: ")+s);}}
 public static string StartupLink {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup),"SecureKon.lnk");}}
 const string Approval="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder";
 public static bool StartupEnabled(){if(!File.Exists(StartupLink))return false;using(var k=Registry.CurrentUser.OpenSubKey(Approval)){byte[] v=k==null?null:k.GetValue("SecureKon.lnk") as byte[];if(v!=null&&v.Length>0){if(v[0]==3||v[0]==7)return false;if(v[0]!=2&&v[0]!=6)throw new Exception(L.T("Başlangıç durumunu Görev Yöneticisi üzerinden kontrol edin."));}}return true;}
 public static void SetStartup(bool enabled){if(!enabled){if(File.Exists(StartupLink))File.Delete(StartupLink);return;}CreateShortcut(StartupLink,Exe,"--startup",L.T("Oturum açıldığında sessiz DNS denetimi"));using(var k=Registry.CurrentUser.OpenSubKey(Approval,true)){if(k!=null)k.DeleteValue("SecureKon.lnk",false);}}
 public static void CreateShortcut(string path,string target,string args,string description){Directory.CreateDirectory(Path.GetDirectoryName(path));dynamic shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));dynamic link=shell.CreateShortcut(path);link.TargetPath=target;link.Arguments=args;link.WorkingDirectory=Path.GetDirectoryName(target);link.Description=description;link.IconLocation=target+",0";link.Save();}
 public static dynamic Scheduler(){dynamic s=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));s.Connect();return s;}
 public static Result Submit(string action,DnsConfig config){
  if(action=="Apply")Validate(config);
  string folder=Path.Combine(Data,"Requests");
  using(var gate=new FileStream(Path.Combine(folder,"client.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)){
   dynamic scheduler=Scheduler();dynamic task=scheduler.GetFolder("\\").GetTask("SecureKon-Worker");
   var watch=Stopwatch.StartNew();while((int)task.State==4){if(watch.Elapsed.TotalSeconds>200)throw new Exception(L.T("Önceki DNS işlemi tamamlanamadı."));Thread.Sleep(300);}
   string id=Guid.NewGuid().ToString("N");Write(Path.Combine(folder,"request.json"),new Request{Id=id,Action=action,Config=config});task.Run(null);watch.Restart();
   while(watch.Elapsed.TotalSeconds<200){Thread.Sleep(350);try{var result=Read<Result>(Path.Combine(Data,"status.json"));if(result.Id==id){if(result.State=="Failed")throw new ApplicationException(L.Error(result.Detail));return result;}}catch(IOException){}catch(ArgumentException){} }
   throw new Exception(L.T("DNS denetimi zaman aşımına uğradı. SecureKon'u açıp tekrar deneyin."));
  }
 }
 public static InstallContext CurrentContext(){return new InstallContext{Language=L.Language,Sid=WindowsIdentity.GetCurrent().User.Value,Programs=Environment.GetFolderPath(Environment.SpecialFolder.Programs),Startup=Environment.GetFolderPath(Environment.SpecialFolder.Startup),Desktop=Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),ParentPid=Process.GetCurrentProcess().Id};}
 public static bool Admin(){return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);}
 public static string Encode(object o){return Convert.ToBase64String(Encoding.UTF8.GetBytes(Json().Serialize(o)));}
 public static InstallContext Decode(string s){return Json().Deserialize<InstallContext>(Encoding.UTF8.GetString(Convert.FromBase64String(s)));}
}
}
