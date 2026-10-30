using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Drawing2D;
namespace SecureKon {
public static class L {
 public static readonly string[] Codes={"tr","en","de","zh"};
 public static readonly string[] Names={"Türkçe","English","Deutsch","简体中文"};
 public static string Language="tr";
 public static readonly Dictionary<string,string[]> Strings=Read();
 static Dictionary<string,string[]> Read(){using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("translations.json"))using(var reader=new StreamReader(stream)){return Core.Json().Deserialize<Dictionary<string,string[]>>(reader.ReadToEnd());}}
 static string Preference {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"SecureKon","language.txt");}}
 public static string ResolveLanguage(string saved,string system){if(Codes.Contains(saved))return saved;string code=(system??"").Split('-','_')[0].ToLowerInvariant();return Codes.Contains(code)?code:"en";}
 public static void Load(){string saved=null;try{if(File.Exists(Preference))saved=File.ReadAllText(Preference).Trim();}catch(IOException){}catch(UnauthorizedAccessException){}Use(ResolveLanguage(saved,CultureInfo.CurrentUICulture.Name));}
 public static void Use(string code){Language=Codes.Contains(code)?code:"en";}
 public static void Save(string code){Use(code);Directory.CreateDirectory(Path.GetDirectoryName(Preference));File.WriteAllText(Preference,Language);}
 public static string T(string text){if(String.IsNullOrEmpty(text))return text;string key=text;string[] values;if(!Strings.TryGetValue(key,out values)){foreach(var pair in Strings){if(pair.Value.Contains(text)){key=pair.Key;values=pair.Value;break;}}}if(values==null)return text;int index=Array.IndexOf(Codes,Language);return index<=0?key:values[index-1];}
 public static string Error(string text){string direct=T(text);if(direct!=text)return direct;foreach(var pair in Strings.OrderByDescending(x=>x.Key.Length)){if(text.Contains(pair.Key))text=text.Replace(pair.Key,T(pair.Key));}return text;}
 public static void Apply(Control control){if(!(control is ComboBox)&&!(control is TextBox))control.Text=T(control.Text);foreach(Control child in control.Controls)Apply(child);}
 public static ComboBox Picker(Control owner,int x,int y,int width,Action changed){
  var box=new ComboBox{Location=new Point(x+width-68,y),Size=new Size(68,32),DropDownStyle=ComboBoxStyle.DropDownList,DrawMode=DrawMode.OwnerDrawFixed,ItemHeight=28,BackColor=Color.FromArgb(27,36,51),ForeColor=Color.White,FlatStyle=FlatStyle.Flat,AccessibleName="Dil / Language / Sprache / 语言"};
  var tip=new ToolTip();box.Items.AddRange(Names);box.SelectedIndex=Array.IndexOf(Codes,Language);tip.SetToolTip(box,Names[box.SelectedIndex]);
  box.DrawItem+=(s,e)=>{e.DrawBackground();if(e.Index>=0){Flag(e.Graphics,Codes[e.Index],new Rectangle(e.Bounds.X+6,e.Bounds.Y+(e.Bounds.Height-22)/2,33,22));}e.DrawFocusRectangle();};
  box.SelectedIndexChanged+=(s,e)=>{if(box.SelectedIndex<0)return;try{Save(Codes[box.SelectedIndex]);tip.SetToolTip(box,Names[box.SelectedIndex]);changed();box.Invalidate();}catch(Exception error){MessageBox.Show(owner,Error(error.Message),"SecureKon",MessageBoxButtons.OK,MessageBoxIcon.Warning);}};
  box.Disposed+=(s,e)=>tip.Dispose();owner.Controls.Add(box);box.BringToFront();return box;
 }
 public static void Flag(Graphics g,string code,Rectangle bounds){
  var saved=g.Save();g.SetClip(bounds);g.TranslateTransform(bounds.X,bounds.Y);g.ScaleTransform(bounds.Width/60f,bounds.Height/40f);g.SmoothingMode=SmoothingMode.AntiAlias;
  if(code=="de"){g.FillRectangle(Brushes.Black,0,0,60,40);using(var red=new SolidBrush(Color.FromArgb(221,0,0)))g.FillRectangle(red,0,13.33f,60,13.34f);using(var gold=new SolidBrush(Color.FromArgb(255,206,0)))g.FillRectangle(gold,0,26.67f,60,13.33f);}
  else if(code=="en"){
   using(var blue=new SolidBrush(Color.FromArgb(1,33,105)))g.FillRectangle(blue,0,0,60,40);
   using(var white=new Pen(Color.White,8)){g.DrawLine(white,0,0,60,40);g.DrawLine(white,0,40,60,0);}
   using(var red=new Pen(Color.FromArgb(200,16,46),3)){g.DrawLine(red,0,0,60,40);g.DrawLine(red,0,40,60,0);}
   g.FillRectangle(Brushes.White,24,0,12,40);g.FillRectangle(Brushes.White,0,14,60,12);
   using(var red=new SolidBrush(Color.FromArgb(200,16,46))){g.FillRectangle(red,26,0,8,40);g.FillRectangle(red,0,16,60,8);}
  }else{
   using(var red=new SolidBrush(code=="tr"?Color.FromArgb(227,10,23):Color.FromArgb(222,41,16))){g.FillRectangle(red,0,0,60,40);
    if(code=="tr"){g.FillEllipse(Brushes.White,12,10,20,20);g.FillEllipse(red,17,12,16,16);Star(g,Brushes.White,35,20,6,-90);}
    else{using(var gold=new SolidBrush(Color.FromArgb(255,222,0))){Star(g,gold,10,10,6,-90);foreach(var point in new[]{new PointF(20,4),new PointF(24,8),new PointF(24,14),new PointF(20,18)})Star(g,gold,point.X,point.Y,2,(float)(Math.Atan2(10-point.Y,10-point.X)*180/Math.PI));}}
   }
  }
  g.Restore(saved);using(var border=new Pen(Color.FromArgb(110,130,150)))g.DrawRectangle(border,bounds);
 }
 static void Star(Graphics g,Brush brush,float x,float y,float radius,float angle){var points=new PointF[10];for(int i=0;i<10;i++){double a=(angle+i*36)*Math.PI/180;float r=i%2==0?radius:radius*0.382f;points[i]=new PointF(x+r*(float)Math.Cos(a),y+r*(float)Math.Sin(a));}g.FillPolygon(brush,points);}

}
public static class TaskOps {
 public static void DeleteIfPresent(dynamic folder,string name){
  dynamic task;
  try{task=folder.GetTask(name);}catch(Exception e){if((uint)e.HResult==0x80070002)return;throw;}
  if((int)task.State==4)task.Stop(0);
  folder.DeleteTask(name,0);
 }
}
}
