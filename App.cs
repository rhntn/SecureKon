using System;
using System.IO;
using System.Drawing;
using System.Linq;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
[assembly: AssemblyTitle("SecureKon")]
[assembly: AssemblyDescription("Şifreli DNS yöneticisi")]
[assembly: AssemblyCompany("SecureKon")]
[assembly: AssemblyProduct("SecureKon")]
[assembly: AssemblyVersion("1.1.3.0")]
namespace SecureKon {
static class App {
 [DllImport("user32.dll")]static extern bool SetProcessDPIAware();
 [STAThread]static void Main(string[] args){
  if(Environment.OSVersion.Platform==PlatformID.Win32NT)SetProcessDPIAware();
  L.Load();Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
  if(args.Contains("--preview")){Application.Run(new MainForm(true));return;}
  if(args.Contains("--startup")){
   try{if(!Core.StartupEnabled())return;Core.Submit("Check",null);}catch(Exception e){using(var i=new NotifyIcon{Icon=SystemIcons.Warning,Visible=true,Text="SecureKon"}){i.ShowBalloonTip(15000,L.T("SecureKon · Ayarlar düzeltilemedi"),L.Error(e.Message),ToolTipIcon.Warning);var end=DateTime.UtcNow.AddSeconds(20);while(DateTime.UtcNow<end){Application.DoEvents();Thread.Sleep(100);}}}return;
  }
  bool created;using(var mutex=new Mutex(true,"Local\\SecureKon-UI",out created)){if(!created)return;Application.Run(new MainForm(false));}
 }
}
public class MainForm:Form {
 Color bg=Color.FromArgb(16,21,31),card=Color.FromArgb(27,36,51),muted=Color.FromArgb(161,174,195),accent=Color.FromArgb(104,224,188);
 LinkLabel about;Label state,status,detail,endpoint;Button toggle,apply,remove;ComboBox providers;Panel custom;TextBox[] fields=new TextBox[5];ProgressBar progress;bool busy,preview,languageChanging;ComboBox language;System.Windows.Forms.Timer timer;DnsConfig current;
 Label TextLabel(string text,int x,int y,int w,int h,float size,Color color){var l=new Label{Text=text,Location=new Point(x,y),Size=new Size(w,h),Font=new Font("Segoe UI",size),ForeColor=color,BackColor=Color.Transparent};Controls.Add(l);return l;}
 Button Btn(string text,int x,int y,int w,int h){var b=new Button{Text=text,Location=new Point(x,y),Size=new Size(w,h),FlatStyle=FlatStyle.Flat,BackColor=accent,ForeColor=bg,Cursor=Cursors.Hand,Font=new Font("Segoe UI",10)};b.FlatAppearance.BorderSize=0;Controls.Add(b);return b;}
 public MainForm(bool previewMode){preview=previewMode;Text="SecureKon";ClientSize=new Size(560,535);BackColor=bg;ForeColor=Color.White;Font=new Font("Segoe UI",10);FormBorderStyle=FormBorderStyle.FixedSingle;MaximizeBox=false;StartPosition=FormStartPosition.CenterScreen;AutoScaleMode=AutoScaleMode.Dpi;try{Icon=Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);}catch{}
  TextLabel("SecureKon",30,25,400,48,27,Color.White);
  TextLabel(L.T("Şifreli DNS · Windows, Chrome ve Edge"),32,79,490,24,10,muted);
  TextLabel(L.T("Başlangıçta çalıştır"),32,126,300,28,15,Color.White);
  state=TextLabel(L.T("Durum okunuyor…"),32,158,300,25,10,accent);
  toggle=Btn(L.T("Etkinleştir"),350,133,178,43);
  TextLabel(L.T("Oturum açıldığında DNS ayarlarını kontrol eder ve düzeltir.\nKapatmak mevcut DNS ayarlarını değiştirmez."),32,192,496,44,9,muted);
  progress=new ProgressBar{Location=new Point(32,244),Size=new Size(496,4),Style=ProgressBarStyle.Marquee,MarqueeAnimationSpeed=25,Visible=false};Controls.Add(progress);
  TextLabel(L.T("DNS sağlayıcısı"),32,266,496,25,11,Color.White);
  providers=new ComboBox{Location=new Point(32,298),Size=new Size(496,32),DropDownStyle=ComboBoxStyle.DropDownList,BackColor=card,ForeColor=Color.White,Font=new Font("Segoe UI",11)};providers.Items.AddRange(new object[]{"AdGuard","Google","Cloudflare",L.T("Özel DNS")});Controls.Add(providers);
  endpoint=TextLabel("",32,342,496,24,9,muted);
  custom=new Panel{Location=new Point(32,343),Size=new Size(496,300),Visible=false,BackColor=bg};Controls.Add(custom);
  string[] names={L.T("Şifreli DNS adresi (HTTPS)"),L.T("Birincil IPv4"),L.T("İkincil IPv4 (isteğe bağlı)"),L.T("Birincil IPv6"),L.T("İkincil IPv6 (isteğe bağlı)")};
  for(int n=0;n<5;n++){var l=new Label{Text=names[n],Location=new Point(0,n*57),Size=new Size(496,21),ForeColor=muted,Font=new Font("Segoe UI",9)};fields[n]=new TextBox{Location=new Point(0,n*57+23),Size=new Size(496,25),BackColor=card,ForeColor=Color.White,BorderStyle=BorderStyle.FixedSingle};custom.Controls.Add(l);custom.Controls.Add(fields[n]);}
  apply=Btn(L.T("Kaydet ve uygula"),32,382,496,42);
  status=TextLabel(L.T("Hazır"),32,440,496,24,10,accent);detail=TextLabel("",32,468,496,30,9,muted);
  remove=Btn(L.T("SecureKon'u kaldır"),32,502,330,26);remove.UseVisualStyleBackColor=false;remove.BackColor=card;remove.ForeColor=Color.White;remove.FlatAppearance.BorderSize=1;remove.FlatAppearance.BorderColor=Color.FromArgb(90,110,135);remove.FlatAppearance.MouseOverBackColor=Color.FromArgb(45,59,78);remove.Font=new Font("Segoe UI",9);
  about=new LinkLabel{Text=L.T("Hakkında"),Location=new Point(382,502),Size=new Size(146,26),TextAlign=ContentAlignment.MiddleRight,LinkColor=accent,ActiveLinkColor=Color.White,VisitedLinkColor=accent,LinkBehavior=LinkBehavior.HoverUnderline,BackColor=bg,Font=new Font("Segoe UI",9)};about.LinkClicked+=(s,e)=>ShowAbout();Controls.Add(about);
  try{current=preview?Core.Presets[0]:Core.Read<DnsConfig>(Path.Combine(Core.Data,"config.json"));}catch{current=Core.Presets[0];}
  Fill(current);providers.SelectedIndexChanged+=(s,e)=>Selection();int chosen=Array.FindIndex(Core.Presets,c=>c.Url==current.Url&&c.IPv4.SequenceEqual(current.IPv4??new string[0])&&c.IPv6.SequenceEqual(current.IPv6??new string[0]));providers.SelectedIndex=chosen<0?3:chosen;
  toggle.Click+=async(s,e)=>await ActionAsync(async()=>{bool on=preview?false:Core.StartupEnabled();await Task.Run(()=>{if(!preview)Core.SetStartup(!on);});status.Text=!on?L.T("Başlangıç denetimi etkinleştirildi."):L.T("Başlangıç denetimi devre dışı.");detail.Text=L.T("Mevcut DNS ayarları korunur.");},L.T("Başlangıç ayarı değiştiriliyor…"));
  apply.Click+=async(s,e)=>await ActionAsync(async()=>{var c=Selected();Core.Validate(c);Result r=preview?new Result{State="Repaired",Timestamp=DateTime.UtcNow.ToString("o")}:await Task.Run(()=>Core.Submit("Apply",c));current=c;status.Text=r.State=="Offline"?L.T("Kaydedildi · Aktif bağlantı yok"):L.T("DNS ayarları uygulandı");detail.Text=r.State=="Offline"?L.T("Bağlantı kurulduğunda yeniden uygulayabilirsiniz."):L.T("Windows, Chrome ve Edge için doğrulandı.");},L.T("DNS ayarları uygulanıyor…"));
  remove.Click+=(s,e)=>Uninstall();
  language=L.Picker(this,350,35,178,()=>{languageChanging=true;try{int selected=providers.SelectedIndex;L.Apply(this);providers.Items[3]=L.T("Özel DNS");providers.SelectedIndex=selected;RefreshStartup();}finally{languageChanging=false;}});
  timer=new System.Windows.Forms.Timer{Interval=2000};timer.Tick+=(s,e)=>{if(!busy)RefreshStartup();};Shown+=(s,e)=>{RefreshStartup();timer.Start();};FormClosing+=(s,e)=>{if(busy)e.Cancel=true;};FormClosed+=(s,e)=>timer.Dispose();
 }
 void Fill(DnsConfig c){fields[0].Text=c.Url;fields[1].Text=c.IPv4.FirstOrDefault()??"";fields[2].Text=c.IPv4.Skip(1).FirstOrDefault()??"";fields[3].Text=c.IPv6.FirstOrDefault()??"";fields[4].Text=c.IPv6.Skip(1).FirstOrDefault()??"";}
 void Selection(){if(languageChanging)return;bool manual=providers.SelectedIndex==3;custom.Visible=manual;endpoint.Visible=!manual;if(!manual){Fill(Core.Presets[providers.SelectedIndex]);endpoint.Text=Core.Presets[providers.SelectedIndex].Url;}int delta=manual?287:0;ClientSize=new Size(560,535+delta);apply.Top=382+delta;status.Top=440+delta;detail.Top=468+delta;remove.Top=502+delta;about.Top=502+delta;}
 DnsConfig Selected(){if(providers.SelectedIndex<3)return Core.Presets[providers.SelectedIndex];return new DnsConfig{Name=L.T("Özel DNS"),Url=fields[0].Text.Trim(),IPv4=new[]{fields[1].Text.Trim(),fields[2].Text.Trim()}.Where(x=>x.Length>0).ToArray(),IPv6=new[]{fields[3].Text.Trim(),fields[4].Text.Trim()}.Where(x=>x.Length>0).ToArray()};}
 void RefreshStartup(){try{bool on=preview||Core.StartupEnabled();state.Text=L.T(on?"Durum: Açık":"Durum: Kapalı");state.ForeColor=on?accent:muted;toggle.Text=on?L.T("Devre dışı bırak"):L.T("Etkinleştir");}catch(Exception e){state.Text=L.T("Durum okunamadı");detail.Text=L.Error(e.Message);}}
 async Task ActionAsync(Func<Task> operation,string message){if(busy)return;busy=true;language.Enabled=toggle.Enabled=apply.Enabled=providers.Enabled=remove.Enabled=custom.Enabled=false;progress.Visible=true;status.Text=message;detail.Text=L.T("Lütfen bekleyin…");try{await operation();}catch(Exception e){status.Text=L.T("İşlem tamamlanamadı");detail.Text=L.Error(e.Message);MessageBox.Show(this,L.Error(e.Message),"SecureKon",MessageBoxButtons.OK,MessageBoxIcon.Warning);}finally{busy=false;language.Enabled=toggle.Enabled=apply.Enabled=providers.Enabled=remove.Enabled=custom.Enabled=true;progress.Visible=false;RefreshStartup();}}
 void ShowAbout(){using(var dialog=new Form{Text=L.T("Hakkında"),ClientSize=new Size(340,165),FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,StartPosition=FormStartPosition.CenterParent,BackColor=bg,ForeColor=Color.White,Font=new Font("Segoe UI",10),ShowInTaskbar=false}){
  dialog.Icon=Icon;
  dialog.Controls.Add(new Label{Text="SecureKon",Location=new Point(25,22),Size=new Size(290,40),Font=new Font("Segoe UI",23,FontStyle.Bold)});
  dialog.Controls.Add(new Label{Text=L.T("Sürüm")+" "+Assembly.GetExecutingAssembly().GetName().Version.ToString(3),Location=new Point(28,70),Size=new Size(285,23),ForeColor=muted});
  var credit=new LinkLabel{Text="Created by OMTY",Location=new Point(28,111),Size=new Size(285,28),LinkColor=accent,ActiveLinkColor=Color.White,VisitedLinkColor=accent,LinkBehavior=LinkBehavior.HoverUnderline};
  credit.LinkClicked+=(s,e)=>{try{Process.Start(new ProcessStartInfo("https://labs.omty.io"){UseShellExecute=true});}catch(Exception error){MessageBox.Show(dialog,L.Error(error.Message),"SecureKon",MessageBoxButtons.OK,MessageBoxIcon.Warning);}};
  dialog.Controls.Add(credit);dialog.ShowDialog(this);
 }}
 void Uninstall(){if(MessageBox.Show(this,L.T("SecureKon, görevleri ve kısayolları kaldırılacak.\n\nMevcut DNS ayarları korunacak. Devam edilsin mi?"),L.T("SecureKon kaldır"),MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;try{if(preview){Close();return;}string temp=Path.Combine(Path.GetTempPath(),"SecureKon-Kaldir-"+Guid.NewGuid().ToString("N")+".exe");File.Copy(Path.Combine(Core.Install,"SecureKonSetup.exe"),temp);var context=Core.Read<InstallContext>(Path.Combine(Core.Data,"install.json"));context.ParentPid=Process.GetCurrentProcess().Id;context.Language=L.Language;Process.Start(new ProcessStartInfo(temp,"--uninstall "+Core.Encode(context)){UseShellExecute=true,Verb="runas"});Close();}catch(Exception e){MessageBox.Show(this,L.Error(e.Message),"SecureKon",MessageBoxButtons.OK,MessageBoxIcon.Warning);}}
}
}
