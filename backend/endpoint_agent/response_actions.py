"""Opt-in endpoint actions. No arbitrary shell commands or unrestricted paths."""
import base64
import hashlib
import ipaddress
import json
import os
import platform
import subprocess
import time
import uuid
from pathlib import Path
from .collectors.capture_state import CaptureState

PROTECTED = {"system","registry","smss.exe","csrss.exe","wininit.exe","services.exe","lsass.exe","winlogon.exe","svchost.exe"}

class SnapshotStore:
    def __init__(self, state_dir, roots, max_bytes=50*1024*1024):
        self.directory=Path(state_dir).resolve() / "snapshots"
        self.directory.mkdir(parents=True,exist_ok=True)
        self.roots=[Path(path).resolve() for path in roots]
        if not self.roots or len(self.roots)>10:raise ValueError("Configure 1–10 snapshot roots")
        for root in self.roots:
            if root in self.directory.parents or self.directory in root.parents or root==self.directory:
                raise ValueError("Snapshot storage and source roots must not overlap")
            if root==Path(root.anchor):raise ValueError("Whole drive snapshots are unsupported")
        self.max_bytes=max_bytes
        self.state=CaptureState(self.directory / "points.sqlite")

    def safe_target(self,index,relative):
        root=self.roots[index]
        parts=Path(relative).parts
        if Path(relative).is_absolute() or any(p in ("..","") for p in parts):raise ValueError("Unsafe snapshot path")
        candidate=root.joinpath(*parts)
        for path in [root,*candidate.parents,candidate]:
            if path==root or root in path.parents:
                if path.is_symlink() or (hasattr(path,"is_junction") and path.is_junction()):raise ValueError("Links and junctions are unsupported")
        resolved=candidate.resolve()
        if not resolved.is_relative_to(root):raise ValueError("Snapshot escaped configured root")
        return candidate

    def create(self):
        identity=uuid.uuid4().hex
        directory=self.directory/identity;directory.mkdir()
        if len(list(self.directory.glob("*/manifest.json")))>=20:raise ValueError("Snapshot retention cap reached; archive existing points before adding more")
        files=[];total=0
        for index,root in enumerate(self.roots):
            if not root.is_dir():raise ValueError("Snapshot root must be an accessible directory")
            for parent,dirs,names in os.walk(root,followlinks=False):
                for name in dirs:
                    self.safe_target(index,str((Path(parent)/name).relative_to(root)))
                for name in sorted(names):
                    path=self.safe_target(index,str((Path(parent)/name).relative_to(root)))
                    before=path.stat();total+=before.st_size
                    if total>self.max_bytes or len(files)>=1000:raise ValueError("Snapshot exceeds configured size or 1000-file cap")
                    with path.open("rb") as stream:data=stream.read(self.max_bytes+1)
                    if len(data)>self.max_bytes:raise ValueError("File exceeds snapshot memory limit")
                    if (before.st_size,before.st_mtime_ns)!=(path.stat().st_size,path.stat().st_mtime_ns):raise ValueError("A snapshot file changed while reading")
                    digest=hashlib.sha256(data).hexdigest();(directory/digest).write_bytes(data)
                    files.append({"root":index,"relative":str(path.relative_to(root)),"sha256":digest,"size":len(data)})
        manifest={"point_id":identity,"roots":[str(root) for root in self.roots],"files":files,"created_at":time.time(),
                  "system":{"platform":platform.platform(),"hostname":platform.node()},"scope":"configured files; no OS, registry or disk-image rollback"}
        encoded=json.dumps(manifest,sort_keys=True).encode();(directory/"manifest.json").write_bytes(encoded)
        self.state.put(identity,{"manifest_sha256":hashlib.sha256(encoded).hexdigest()})
        return {"point_id":identity,"files":len(files),"bytes":total,"scope":manifest["scope"],"verified":self.verify(identity)["verified"]}

    def manifest(self,identity):
        if len(identity)!=32 or any(c not in "0123456789abcdef" for c in identity):raise ValueError("Invalid rollback point")
        known=self.state.get(identity)
        if not known:raise ValueError("Rollback point is unknown or incomplete")
        directory=self.directory/identity
        if directory.is_symlink():raise ValueError("Snapshot link rejected")
        with (directory/"manifest.json").open("rb") as stream:encoded=stream.read(2*1024*1024+1)
        if len(encoded)>2*1024*1024:raise ValueError("Snapshot manifest exceeds limit")
        if hashlib.sha256(encoded).hexdigest()!=known["manifest_sha256"]:raise ValueError("Snapshot manifest was changed")
        manifest=json.loads(encoded)
        if manifest["roots"]!=[str(root) for root in self.roots]:raise ValueError("Snapshot roots changed; refuse rollback")
        return manifest

    @staticmethod
    def file_digest(path,size):
        with path.open("rb") as stream:data=stream.read(size+1)
        return hashlib.sha256(data).hexdigest()

    def verify(self,identity):
        manifest=self.manifest(identity);mismatches=[]
        for item in manifest["files"]:
            target=self.safe_target(item["root"],item["relative"])
            if not target.is_file() or target.stat().st_size!=item["size"] or self.file_digest(target,item["size"])!=item["sha256"]:
                mismatches.append(item["relative"])
        return {"point_id":identity,"verified":not mismatches,"mismatches":mismatches,"scope":manifest["scope"]}

    def rollback(self,identity):
        manifest=self.manifest(identity)
        # Verify every blob and destination before any mutation.
        blobs={}
        for item in manifest["files"]:
            self.safe_target(item["root"],item["relative"])
            blob=self.directory/identity/item["sha256"]
            if blob.is_symlink() or blob.stat().st_size!=item["size"]:raise ValueError("Snapshot data is corrupt")
            with blob.open("rb") as stream:data=stream.read(item["size"]+1)
            if hashlib.sha256(data).hexdigest()!=item["sha256"]:raise ValueError("Snapshot data is corrupt")
            blobs[item["sha256"]]=data
        backup=self.create()
        for item in manifest["files"]:
            target=self.safe_target(item["root"],item["relative"]);target.parent.mkdir(parents=True,exist_ok=True)
            temporary=target.with_name(target.name+".restore-"+uuid.uuid4().hex)
            with temporary.open("xb") as stream:stream.write(blobs[item["sha256"]])
            self.safe_target(item["root"],item["relative"])
            os.replace(temporary,target)
        result=self.verify(identity);result["backup_point_id"]=backup["point_id"]
        result["note"]="Only captured files restored; new files, permissions and OS state are preserved."
        return result

class WindowsIsolation:
    GROUP="ZANAQ Endpoint Isolation"
    def __init__(self,management_addresses, runner=None):
        # Exclude only explicitly approved management endpoints; DNS must remain reachable
        # through an explicitly listed resolver if the server URL uses a host name.
        self.allowed=[ipaddress.ip_address(value) for value in management_addresses]
        if not self.allowed or len(self.allowed)>10:raise ValueError("Configure management IP exceptions")
        self.runner=runner or self._run

    @staticmethod
    def _run(script):
        if os.name!="nt":raise ValueError("Network isolation adapter supports Windows only")
        encoded=base64.b64encode(script.encode("utf-16-le")).decode()
        result=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-EncodedCommand",encoded],capture_output=True,text=True,timeout=45,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        if result.returncode:raise ValueError((result.stderr or "Firewall command failed")[:1000])
        return json.loads(result.stdout or "{}")

    def ranges(self):
        result=[]
        for version,bits in ((4,32),(6,128)):
            cursor=0
            for value in sorted({int(ip) for ip in self.allowed if ip.version==version}):
                if cursor<value:result.append(f"{ipaddress.ip_address(cursor) if version==4 else ipaddress.IPv6Address(cursor)}-{ipaddress.ip_address(value-1) if version==4 else ipaddress.IPv6Address(value-1)}")
                cursor=value+1
            if cursor<2**bits:result.append(f"{ipaddress.IPv4Address(cursor) if version==4 else ipaddress.IPv6Address(cursor)}-{ipaddress.IPv4Address(2**bits-1) if version==4 else ipaddress.IPv6Address(2**bits-1)}")
        return result

    def isolate(self):
        ranges=json.dumps(self.ranges()).replace("'","''")
        script=f"""$ErrorActionPreference='Stop'
$addresses=ConvertFrom-Json '{ranges}'
if ((Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {{$_.Enabled -ne 'True'}})) {{throw 'Firewall profiles must already be enabled'}}
try {{
foreach ($direction in @('Inbound','Outbound')) {{
$name='ZANAQ-Isolation-'+$direction
if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {{ Set-NetFirewallRule -Name $name -RemoteAddress $addresses -Enabled True -Action Block -Profile Any }} else {{ New-NetFirewallRule -Name $name -DisplayName $name -Group '{self.GROUP}' -Direction $direction -Action Block -RemoteAddress $addresses -Enabled True -Profile Any | Out-Null }}
}}
}} catch {{ Get-NetFirewallRule -Group '{self.GROUP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; throw }}
@{{isolated=$true; exceptions=(@({json.dumps([str(ip) for ip in self.allowed])[1:-1]})); scope='Host firewall IP isolation; management exceptions retain connectivity'}} | ConvertTo-Json -Compress
"""
        result=self.runner(script)
        status=self.status()
        if not status.get("isolated"):raise ValueError("Firewall rules did not become active")
        return {**result,**status}

    def release(self):
        result=self.runner(f"$ErrorActionPreference='Stop'; Get-NetFirewallRule -Group '{self.GROUP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; @{{released=$true}} | ConvertTo-Json -Compress")
        status=self.status()
        if status.get("isolated"):raise ValueError("Isolation rules remain active")
        return {**result,**status}

    def status(self):
        return self.runner(f"$ErrorActionPreference='Stop'; $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Group '{self.GROUP}' -ErrorAction SilentlyContinue | Where-Object {{$_.Enabled -eq 'True' -and $_.Action -eq 'Block'}}); @{{isolated=($rules.Count -eq 2); rules=$rules.Count}} | ConvertTo-Json -Compress")

class WindowsRestore:
    """Native Windows client System Restore; completion is checked after reboot."""
    def __init__(self,state_dir,runner=None):
        self.state=CaptureState(Path(state_dir)/"windows-restore.sqlite")
        self.runner=runner or WindowsIsolation._run

    def create(self):
        identity=uuid.uuid4().hex;description="ZANAQ-"+identity
        detail=self.runner(f"""$ErrorActionPreference='Stop'
Checkpoint-Computer -Description '{description}' -RestorePointType MODIFY_SETTINGS
$point=Get-ComputerRestorePoint | Where-Object {{$_.Description -eq '{description}'}} | Select-Object -First 1
if (-not $point) {{throw 'Windows did not create the requested restore point (System Protection or daily limit)'}}
@{{sequence=[int]$point.SequenceNumber; description=$point.Description}} | ConvertTo-Json -Compress
""")
        if not isinstance(detail.get("sequence"),int):raise ValueError("Windows returned no restore point sequence")
        self.state.put(identity,{**detail,"created_at":time.time()})
        return {"point_id":identity,"scope":"windows_system","sequence":detail["sequence"],"verified":True,
            "note":"Native System Restore point exists; protects Windows system files/settings, not personal files or a complete disk image."}

    def point(self,identity):
        if len(identity)!=32 or any(c not in "0123456789abcdef" for c in identity):raise ValueError("Invalid restore point")
        point=self.state.get(identity)
        if not point:raise ValueError("Unknown native Windows restore point")
        return point

    def rollback(self,identity):
        point=self.point(identity);sequence=int(point["sequence"])
        before=self.runner("$ErrorActionPreference='Stop'; @{boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress")
        self.state.put(identity,{**point,"requested_at":time.time(),"boot_before":before["boot"]})
        # This only schedules the restore/reboot; it never claims completion here.
        result=self.runner(f"""$ErrorActionPreference='Stop'
$point=Get-ComputerRestorePoint -RestorePoint {sequence}
if (-not $point -or $point.Description -ne '{point['description']}') {{throw 'Restore point no longer exists'}}
$code=([WMIClass]'root/default:SystemRestore').Restore({sequence})
if ($code -ne 0) {{throw ('Windows restore request failed: '+$code)}}
shutdown.exe /r /t 30 /d p:4:1 /c 'ZANAQ approved system restore'
if ($LASTEXITCODE -ne 0) {{throw 'Restore requested but restart could not be scheduled'}}
@{{restart_scheduled=$true}} | ConvertTo-Json -Compress
""")
        return {"point_id":identity,"scope":"windows_system","restart_scheduled":bool(result.get("restart_scheduled")),"verified":False,
                "note":"Restore requested. Reconnect after restart and verify the Windows-reported restore status."}

    def verify(self,identity):
        point=self.point(identity)
        if not point.get("requested_at"):raise ValueError("No rollback was requested for this point")
        observed=self.runner("$ErrorActionPreference='Stop'; @{boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o'); restore_status=([WMIClass]'root/default:SystemRestore').GetLastRestoreStatus()} | ConvertTo-Json -Compress")
        restarted=observed["boot"]!=point["boot_before"]
        return {"point_id":identity,"scope":"windows_system","restarted":restarted,"windows_restore_status":observed["restore_status"],
                "verified":restarted and observed["restore_status"]==1,
                "note":"Verification uses Windows' last restore result after a new boot; it does not compare every OS file or prove the requested point's identity."}

class ResponseExecutor:
    def __init__(self,config,state_dir,desktop=None,ps=None,isolation=None):
        self.config=config;self.state_dir=Path(state_dir);self.state_dir.mkdir(parents=True,exist_ok=True)
        self.state=CaptureState(self.state_dir/"commands.sqlite")
        self.desktop=desktop;self.ps=ps;self.isolation=isolation

    def execute(self,command):
        key=str(command["id"]);previous=self.state.get(key)
        if previous:
            return previous.get("result") or {"state":"indeterminate","detail":{"error":"Agent restarted during execution; action will not be repeated"}}
        if not self.config.get("enabled",False):return {"state":"failed","detail":{"error":"Endpoint response is disabled locally"}}
        from datetime import datetime,timezone
        if datetime.fromisoformat(command["expires_at"].replace("Z","+00:00"))<=datetime.now(timezone.utc):
            return {"state":"failed","detail":{"error":"Command expired before execution"}}
        # An atomic SQLite claim prevents two workers from executing the same action.
        with self.state.connect() as journal:
            claimed=journal.execute("INSERT OR IGNORE INTO checkpoints VALUES (?,?)",(key,json.dumps({"started":time.time()}))).rowcount
        if not claimed:
            previous=self.state.get(key)
            return previous.get("result") or {"state":"indeterminate","detail":{"error":"Another worker claimed this command; execution will not be repeated"}}
        try:
            action=command["action"];args=command["arguments"]
            if action not in self.config.get("allowed_actions",[]):raise ValueError("Action is not enabled locally")
            if action=="process_list":
                if self.ps is None:import psutil;self.ps=psutil
                entries=[]
                for process in self.ps.process_iter(["pid","name","create_time","username"]):
                    entries.append(process.info)
                    if len(entries)>=500:break
                detail={"processes":entries,"partial":len(entries)>=500}
            elif action=="process_terminate":
                if self.ps is None:import psutil;self.ps=psutil
                pid=int(args["pid"])
                if pid<=4 or pid in (os.getpid(),os.getppid()):raise ValueError("Protected process")
                process=self.ps.Process(pid)
                if abs(process.create_time()-float(args["create_time"]))>0.001:raise ValueError("PID was reused; request a fresh process list")
                if process.name().lower() in PROTECTED:raise ValueError("Protected system process")
                process.terminate()
                try:process.wait(timeout=5)
                except self.ps.TimeoutExpired:raise ValueError("Termination requested but process still running; no force-kill performed")
                detail={"pid":pid,"create_time":args["create_time"],"terminated":True}
            elif action in ("isolate","release","isolation_status"):
                if self.isolation is None:self.isolation=WindowsIsolation(self.config.get("management_addresses",[]))
                if action=="isolate" and self.config.get("server_url"):
                    import socket
                    from urllib.parse import urlparse
                    hostname=urlparse(self.config["server_url"]).hostname
                    resolved={ipaddress.ip_address(entry[4][0]) for entry in socket.getaddrinfo(hostname,None)}
                    if not resolved or not resolved.issubset(set(self.isolation.allowed)):
                        raise ValueError("All resolved management server addresses must be configured as isolation exceptions")
                detail=getattr(self.isolation,action.replace("isolation_status","status"))()
            elif action in ("snapshot","rollback","verify_rollback"):
                if args.get("scope","files")=="windows_system":
                    if not self.config.get("windows_restore_enabled",False):raise ValueError("Native Windows System Restore is disabled locally")
                    store=WindowsRestore(self.state_dir)
                else:store=SnapshotStore(self.state_dir,self.config.get("snapshot_roots",[]))
                detail=store.create() if action=="snapshot" else store.rollback(args["point_id"]) if action=="rollback" else store.verify(args["point_id"])
                if not detail.get("verified") and not detail.get("restart_scheduled"):
                    result={"state":"failed","detail":{**detail,"error":"Rollback verification did not confirm the requested state"}}
                    self.state.put(key,{"result":result})
                    return result
            elif action in ("live_start","live_stop","control_input"):
                if self.desktop is None:raise ValueError("Desktop adapter unavailable")
                detail=getattr(self.desktop,{"live_start":"start","live_stop":"stop","control_input":"input"}[action])(args,command["actor"])
            else:raise ValueError("Unsupported action")
            result={"state":"pending_verification" if detail.get("restart_scheduled") else "succeeded","detail":detail}
        except Exception as error:
            result={"state":"failed","detail":{"error":str(error)[:2000]}}
        self.state.put(key,{"result":result})
        return result
