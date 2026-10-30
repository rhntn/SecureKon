using System;
using System.IO;
using System.Runtime.InteropServices;
using SecureKon;
public class FakeTask {public int State{get;set;} public bool Stopped;public void Stop(int flags){Stopped=true;}}
public class FakeFolder {public Exception Failure;public FakeTask Task=new FakeTask();public bool Deleted;public FakeTask GetTask(string name){if(Failure!=null)throw Failure;return Task;}public void DeleteTask(string name,int flags){Deleted=true;}}
class TestRegression {
 static void Assert(bool value,string message){if(!value)throw new Exception(message);}
 static void Main(){
  Exception mapped=Marshal.GetExceptionForHR(unchecked((int)0x80070002));
  Assert(mapped is FileNotFoundException,"Runtime must map FILE_NOT_FOUND to FileNotFoundException");
  bool oldFailed=false;try{try{throw mapped;}catch(COMException){}}catch(FileNotFoundException){oldFailed=true;}
  Assert(oldFailed,"Old missing-task catch unexpectedly handled mapped exception");
  foreach(var exception in new Exception[]{mapped,new COMException("missing",unchecked((int)0x80070002))}){var folder=new FakeFolder{Failure=exception};TaskOps.DeleteIfPresent(folder,"SecureKon-Worker");Assert(!folder.Deleted,"Missing task should not be deleted");}
  foreach(var exception in new Exception[]{new UnauthorizedAccessException(),new COMException("denied",unchecked((int)0x80070005)),new IOException("other IO error")}){bool threw=false;try{TaskOps.DeleteIfPresent(new FakeFolder{Failure=exception},"SecureKon-Worker");}catch(Exception){threw=true;}Assert(threw,"Real error was suppressed");}
  foreach(int state in new[]{3,4}){var folder=new FakeFolder();folder.Task.State=state;TaskOps.DeleteIfPresent(folder,"SecureKon-Worker");Assert(folder.Deleted,"Existing task not removed");Assert(folder.Task.Stopped==(state==4),"Only running tasks should be stopped");}
  Console.WriteLine("Missing-task regression: reproduced old failure; fixed mapped/COM paths; other failures propagate PASS");
  foreach(var item in L.Strings){Assert(item.Value.Length==3,"Missing translation");for(int i=0;i<3;i++){Assert(!String.IsNullOrWhiteSpace(item.Value[i]),"Empty translation");L.Use(L.Codes[i+1]);Assert(L.T(item.Key)==item.Value[i],"Wrong language");}}
  foreach(string source in L.Codes){L.Use(source);string install=L.T("Kur");foreach(string target in L.Codes){L.Use(target);Assert(L.T(install)==L.T("Kur"),"Live language switch failed");}}
  L.Use("de");Assert(L.Error("Geçersiz DNS adresi: 127.0.0.1").Contains("Ungültige DNS-Adresse"),"Error not translated");
  var context=new InstallContext{Language="zh",Sid="S-1-5-21-123-456-789-1001"};Assert(Core.Decode(Core.Encode(context)).Language=="zh","Elevation lost language");
  foreach(var config in Core.Presets)Core.Validate(config);
  Console.WriteLine("Four languages, switching, error translation, elevation context and DNS presets PASS ("+L.Strings.Count+" strings)");
 }
}
