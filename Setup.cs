using System;
using System.IO;
using System.Drawing;
using System.Diagnostics;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
[assembly: AssemblyTitle("SecureKon Setup")]
[assembly: AssemblyProduct("SecureKon")]
[assembly: AssemblyVersion("1.1.3.0")]
namespace SecureKon {
static class Setup {
 static string stage="Kurulum başlatılıyor";
 const string UninstallKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SecureKon";
 [STAThread] static int Main(string[] args){L.Load();Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);try{
 if(args.Length==2&&args[0]=="--install"){if(!Core.Admin())throw new Exception(L.T("Kurulum için yönetici izni gerekli."));var ctx=Core.Decode(args[1]);L.Use(ctx.Language);Install(ctx);return 0;}
 if(args.Length==2&&args[0]=="--uninstall"){if(!Core.Admin())throw new Exception(L.T("Kaldırmak için yönetici izni gerekli."));var ctx=Core.Decode(args[1]);L.Use(ctx.Language);stage="Kaldırılıyor";Remove(ctx);MessageBox.Show(L.T("SecureKon kaldırıldı. Mevcut DNS ayarları korundu."),"SecureKon");return 0;}
 if(args.Length==1&&args[0]=="--remove"){if(MessageBox.Show(L.T("SecureKon kaldırılsın mı? Mevcut DNS ayarları korunur."),"SecureKon",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return 0;var ctx=Core.Read<InstallContext>(Path.Combine(Core.Data,"install.json"));ctx.ParentPid=Process.GetCurrentProcess().Id;ctx.Language=L.Language;string temp=Path.Combine(Path.GetTempPath(),"SecureKon-Kaldir-"+Guid.NewGuid().ToString("N")+".exe");File.Copy(Application.ExecutablePath,temp);Process.Start(new ProcessStartInfo(temp,"--uninstall "+Core.Encode(ctx)){UseShellExecute=true,Verb="runas"});return 0;}
 Application.Run(new SetupForm());return 0;
 }catch(Exception e){string log="";try{log=Path.Combine(Path.GetTempPath(),"SecureKon-Setup-"+Guid.NewGuid().ToString("N")+".log");using(var file=new FileStream(log,FileMode.CreateNew,FileAccess.Write))using(var writer=new StreamWriter(file)){writer.WriteLine(DateTime.UtcNow.ToString("o"));writer.WriteLine("Stage: "+stage);writer.WriteLine(e.ToString());}}catch{log="";}MessageBox.Show(L.T("Aşama: ")+L.T(stage)+"\n\n"+L.Error(e.Message)+(log.Length>0?"\n\n"+L.T("Hata kaydı: ")+log:""),"SecureKon",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}}
 static void SafeDirectory(string path){string p=Path.GetFullPath(path);while(!String.IsNullOrEmpty(p)){if(Directory.Exists(p)&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new Exception(L.T("Bağlantılı klasör kullanılamaz: ")+p);p=Path.GetDirectoryName(p);}}
 static void Protect(string path,string sid,bool writable){SafeDirectory(path);Directory.CreateDirectory(path);var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null));foreach(var id in new[]{new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null)})acl.AddAccessRule(new FileSystemAccessRule(id,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),writable?FileSystemRights.Modify:FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.SetAccessControl(path,acl);}
 static void Extract(string name){string dst=Path.Combine(Core.Install,name);if(File.Exists(dst)&&(File.GetAttributes(dst)&FileAttributes.ReparsePoint)!=0)throw new Exception(L.T("Geçersiz kurulum dosyası."));using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream(name)){if(input==null)throw new Exception(L.T("Eksik kurulum bileşeni: ")+name);using(var output=File.Create(dst))input.CopyTo(output);}}
 static void DeleteTask(string name){dynamic service=Core.Scheduler();TaskOps.DeleteIfPresent(service.GetFolder("\\"),name);}
 static bool Enabled(InstallContext ctx,string name){string link=Path.Combine(ctx.Startup,name+".lnk");if(!File.Exists(link))return false;using(var key=Registry.Users.OpenSubKey(ctx.Sid+"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder")){var value=key==null?null:key.GetValue(name+".lnk") as byte[];return value==null||value.Length==0||value[0]==2||value[0]==6;}}
 static void RemoveApproval(InstallContext ctx,string name){using(var key=Registry.Users.OpenSubKey(ctx.Sid+"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder",true)){if(key!=null)key.DeleteValue(name+".lnk",false);}}
 static void Install(InstallContext ctx){
 stage="Sistem kontrolü";
 new SecurityIdentifier(ctx.Sid);if(!Path.IsPathRooted(ctx.Programs)||!Path.IsPathRooted(ctx.Startup))throw new Exception(L.T("Geçersiz kullanıcı klasörü."));
 using(var key=Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")){int build; if(!Int32.TryParse(Convert.ToString(key.GetValue("CurrentBuildNumber")),out build)||build<22000)throw new Exception(L.T("SecureKon, Windows 11 gerektirir."));}
 stage="Mevcut ayarlar okunuyor";string legacy=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"Notion3");bool updating=File.Exists(Path.Combine(Core.Data,"config.json"));bool migrating=File.Exists(Path.Combine(legacy,"config.json"));bool enabled=updating?Enabled(ctx,"SecureKon"):migrating?Enabled(ctx,"Notion3"):true;
 DnsConfig config=Core.Presets[0];if(updating)config=Core.Read<DnsConfig>(Path.Combine(Core.Data,"config.json"));else if(migrating)config=Core.Read<DnsConfig>(Path.Combine(legacy,"config.json"));Core.Validate(config);
 foreach(var proc in Process.GetProcessesByName("SecureKon")){try{if(String.Equals(proc.MainModule.FileName,Core.Exe,StringComparison.OrdinalIgnoreCase))throw new Exception(L.T("Önce açık SecureKon penceresini kapatın, sonra kurulumu tekrar başlatın."));}catch(System.ComponentModel.Win32Exception){}}
 // Refuse precreated or modified protected locations rather than trusting inherited file ACLs.
 foreach(string path in new[]{Core.Install,Core.Data}){SafeDirectory(path);if(Directory.Exists(path)){var owner=Directory.GetAccessControl(path).GetOwner(typeof(SecurityIdentifier)).Value;if(owner!="S-1-5-18"&&owner!="S-1-5-32-544")throw new Exception(L.T("Kurulum klasörünün sahibi doğrulanamadı: ")+path);}}
 stage="Görev kontrolü";DeleteTask("SecureKon-Worker");stage="Dosyalar kuruluyor";Protect(Core.Install,ctx.Sid,false);Protect(Core.Data,ctx.Sid,false);Protect(Path.Combine(Core.Data,"Requests"),ctx.Sid,true);
 Extract("SecureKon.exe");Extract("Engine.ps1");Extract("Config.ps1");string installer=Path.Combine(Core.Install,"SecureKonSetup.exe");if(!String.Equals(Application.ExecutablePath,installer,StringComparison.OrdinalIgnoreCase))File.Copy(Application.ExecutablePath,installer,true);
 Core.Write(Path.Combine(Core.Data,"config.json"),config);Core.Write(Path.Combine(Core.Data,"install.json"),ctx);
 stage="Yetkili görev kaydediliyor";dynamic service=Core.Scheduler();dynamic def=service.NewTask(0);def.RegistrationInfo.Description=L.T("SecureKon: doğrulanmış DNS ayarlarını uygular. Başlangıç kısayolu tarafından çağrılır.");def.Principal.UserId="S-1-5-18";def.Principal.LogonType=5;def.Principal.RunLevel=1;def.Settings.Enabled=true;def.Settings.AllowDemandStart=true;def.Settings.DisallowStartIfOnBatteries=false;def.Settings.StopIfGoingOnBatteries=false;def.Settings.ExecutionTimeLimit="PT3M";def.Settings.MultipleInstances=2;def.Settings.Hidden=true;
 dynamic action=def.Actions.Create(0);action.Path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32\\WindowsPowerShell\\v1.0\\powershell.exe");action.Arguments="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \""+Path.Combine(Core.Install,"Engine.ps1")+"\"";action.WorkingDirectory=Core.Install;
 string sddl="D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;"+ctx.Sid+")";service.GetFolder("\\").RegisterTaskDefinition("SecureKon-Worker",def,6,"SYSTEM",null,5,sddl);
 stage="Kısayollar oluşturuluyor";Core.CreateShortcut(Path.Combine(ctx.Programs,"SecureKon.lnk"),Core.Exe,"",L.T("SecureKon DNS yöneticisi"));string startup=Path.Combine(ctx.Startup,"SecureKon.lnk");if(enabled){Core.CreateShortcut(startup,Core.Exe,"--startup",L.T("Oturum açıldığında DNS ayarlarını denetler"));RemoveApproval(ctx,"SecureKon");}else if(File.Exists(startup))File.Delete(startup);
 using(var key=Registry.LocalMachine.CreateSubKey(UninstallKey)){key.SetValue("DisplayName","SecureKon");key.SetValue("DisplayVersion","1.1.3");key.SetValue("Publisher","SecureKon");key.SetValue("DisplayIcon",Core.Exe);key.SetValue("InstallLocation",Core.Install);key.SetValue("UninstallString","\""+installer+"\" --remove");key.SetValue("NoModify",1,RegistryValueKind.DWord);key.SetValue("NoRepair",1,RegistryValueKind.DWord);}
 if(migrating){stage="Eski görevler kaldırılıyor";DeleteTask("Notion3-Guard");DeleteTask("Notion3-Notify");foreach(var directory in new[]{ctx.Programs,ctx.Startup}){string file=Path.Combine(directory,"Notion3.lnk");if(File.Exists(file))File.Delete(file);}RemoveApproval(ctx,"Notion3");}
 }
 static void Remove(InstallContext ctx){if(ctx.ParentPid!=Process.GetCurrentProcess().Id){try{Process.GetProcessById(ctx.ParentPid).WaitForExit(30000);}catch(ArgumentException){}}
 DeleteTask("SecureKon-Worker");foreach(var proc in Process.GetProcessesByName("SecureKon")){try{if(String.Equals(proc.MainModule.FileName,Core.Exe,StringComparison.OrdinalIgnoreCase)){proc.CloseMainWindow();if(!proc.WaitForExit(5000))throw new Exception(L.T("SecureKon penceresini kapatıp kaldırmayı tekrar deneyin."));}}catch(System.ComponentModel.Win32Exception){}}
 foreach(string directory in new[]{ctx.Programs,ctx.Startup}){string path=Path.Combine(directory,"SecureKon.lnk");if(File.Exists(path))File.Delete(path);}RemoveApproval(ctx,"SecureKon");Registry.LocalMachine.DeleteSubKeyTree(UninstallKey,false);
 foreach(var folder in new[]{Core.Install,Core.Data}){SafeDirectory(folder);if(Directory.Exists(folder)){foreach(var sub in Directory.GetDirectories(folder,"*",SearchOption.AllDirectories))SafeDirectory(sub);Directory.Delete(folder,true);}}
 }
}
class SetupForm:Form {
 Button install;Label info;ProgressBar progress;bool busy;ComboBox language;
 public SetupForm(){try{Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath);}catch{}Text=L.T("SecureKon · Kurulum");ClientSize=new Size(480,310);BackColor=Color.FromArgb(16,21,31);ForeColor=Color.White;Font=new Font("Segoe UI",10);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;StartPosition=FormStartPosition.CenterScreen;
 Controls.Add(new Label{Text="SecureKon",Font=new Font("Segoe UI",26,FontStyle.Bold),AutoSize=true,Location=new Point(28,25)});
 info=new Label{Text=L.T("Windows, Chrome ve Edge için DNS yönetimi.\n\nKurulumda bir kez yönetici izni gerekir.\nGünlük kullanımda tekrar izin istenmez.\nKısayol Başlat menüsüne eklenir."),Location=new Point(30,88),Size=new Size(420,120)};Controls.Add(info);
 progress=new ProgressBar{Location=new Point(30,220),Size=new Size(420,5),Style=ProgressBarStyle.Marquee,Visible=false};Controls.Add(progress);
 install=new Button{Text=L.T("Kur"),Location=new Point(30,246),Size=new Size(420,40),FlatStyle=FlatStyle.Flat,BackColor=Color.FromArgb(104,224,188),ForeColor=Color.FromArgb(16,21,31)};install.Click+=async(s,e)=>{if(install.Text==L.T("SecureKon'u aç")){Process.Start(Core.Exe);Close();return;}busy=true;language.Enabled=false;install.Enabled=false;progress.Visible=true;info.Text=L.T("SecureKon kuruluyor…\n\nWindows yönetici izni penceresini onaylayın.");try{string context=Core.Encode(Core.CurrentContext());var process=Process.Start(new ProcessStartInfo(Application.ExecutablePath,"--install "+context){UseShellExecute=true,Verb="runas"});await Task.Run(()=>process.WaitForExit());if(process.ExitCode!=0)throw new Exception(L.T("Kurulum tamamlanamadı. Gösterilen hatayı giderip yeniden deneyin."));info.Text=L.T("Kurulum tamamlandı.\n\nDNS sağlayıcınızı seçmek ve ayarları uygulamak için\nSecureKon'u açın.");install.Text=L.T("SecureKon'u aç");}catch(Exception ex){info.Text=L.Error(ex.Message);}finally{busy=false;language.Enabled=true;progress.Visible=false;install.Enabled=true;}};Controls.Add(install);language=L.Picker(this,300,35,150,()=>L.Apply(this));FormClosing+=(s,e)=>{if(busy)e.Cancel=true;};}
}
}
