"""Visible, time-limited primary-display capture and input, with local consent."""
import base64
import io
import threading
import time
from datetime import datetime,timezone

KEYS={"enter","esc","tab","backspace","delete","up","down","left","right","space","home","end","pageup","pagedown"}

class DesktopController:
    def __init__(self,config,consent=None,capture=None,automation=None):
        self.config=config;self.consent=consent or self._visible_consent
        self.capture=capture;self.automation=automation;self.active=None;self.closed=None
        self.stop_event=threading.Event();self.ready=threading.Event();self.last_frame=0;self.sequence=0

    def _visible_consent(self,actor,mode,duration):
        self.ready.clear();decision={"allowed":False}
        def display():
            try:
                import tkinter as tk
                window=tk.Tk();window.title("ZANAQ remote session request")
                window.attributes("-topmost",True)
                tk.Label(window,text=f"{actor} requests desktop {mode} for {duration} seconds.\nThe screen will be recorded. You can stop at any time.",padx=20,pady=20).pack()
                def stop():self.stop_event.set();window.destroy();self.ready.set()
                def accept():
                    decision["allowed"]=True;self.ready.set()
                    for widget in window.winfo_children():widget.destroy()
                    tk.Label(window,text=f"Desktop {mode} and recording active: {actor}",padx=15,pady=8).pack()
                    tk.Button(window,text="Stop remote session",command=stop).pack()
                    window.after(duration*1000,stop)
                tk.Button(window,text="Allow this session",command=accept).pack()
                tk.Button(window,text="Decline",command=stop).pack()
                window.protocol("WM_DELETE_WINDOW",stop)
                def watch():
                    if self.stop_event.is_set():window.destroy()
                    else:window.after(250,watch)
                window.after(250,watch)
                window.after(30000,lambda:stop() if not decision["allowed"] else None)
                window.mainloop()
            except Exception:self.stop_event.set();self.ready.set()
        threading.Thread(target=display,daemon=True).start()
        self.ready.wait(31)
        return decision["allowed"] and not self.stop_event.is_set()

    def start(self,args,actor):
        if not self.config.get("desktop_enabled",False):raise ValueError("Desktop sessions are disabled locally")
        if self.active and not self.stop_event.is_set():raise ValueError("A desktop session is already active")
        if args["mode"]=="control" and not self.config.get("control_enabled",False):raise ValueError("Remote input is disabled locally")
        if self.capture is None:
            from PIL import ImageGrab
            self.capture=ImageGrab.grab
        if args["mode"]=="control" and self.automation is None:
            import pyautogui
            pyautogui.FAILSAFE=True
            self.automation=pyautogui
        self.stop_event.clear()
        if not self.consent(actor,args["mode"],args["duration"]):raise ValueError("Local user declined or desktop consent is unavailable")
        self.active={**args,"actor":actor,"deadline":time.monotonic()+args["duration"]}
        self.sequence=0;self.last_frame=0
        return {"session_id":args["session_id"],"connected":True,"mode":args["mode"],"local_consent":True,"recording":True}

    def stop(self,args,actor=""):
        if self.active and self.active["session_id"]!=args["session_id"]:raise ValueError("Different desktop session")
        self.stop_event.set()
        if self.active:self.closed={"session_id":self.active["session_id"],"reason":"stopped"}
        self.active=None
        return {"session_id":args["session_id"],"stopped":True}

    def live(self):
        if self.active and (self.stop_event.is_set() or time.monotonic()>=self.active["deadline"]):
            self.stop({"session_id":self.active["session_id"]})
        return self.active

    def input(self,args,actor):
        session=self.live()
        if not session or session["session_id"]!=args["session_id"] or session["mode"]!="control" or session["actor"]!=actor:
            raise ValueError("No consented control session for this operator")
        event=args["event"];auto=self.automation
        if event=="click":
            width,height=auto.size();auto.click(round(args["x"]*(width-1)),round(args["y"]*(height-1)))
        elif event=="key":
            if args["key"] not in KEYS:raise ValueError("Unsupported key")
            auto.press(args["key"])
        elif event=="text":
            if any(ord(c)<32 or ord(c)>126 for c in args["text"]):raise ValueError("Remote text input supports printable ASCII only")
            auto.write(args["text"],interval=0.01)
        elif event=="scroll":auto.scroll(args["amount"])
        else:raise ValueError("Unsupported input event")
        return {"session_id":session["session_id"],"input_applied":True,"event":event}

    def frame(self):
        session=self.live()
        if not session or time.monotonic()-self.last_frame<1:return None
        self.last_frame=time.monotonic()
        try:
            image=self.capture().convert("RGB");image.thumbnail((1280,720))
            stream=io.BytesIO();image.save(stream,format="JPEG",quality=55)
            if stream.tell()>512*1024:raise ValueError("Desktop image exceeds recording limit")
            result={"sequence":self.sequence,"occurred_at":datetime.now(timezone.utc).isoformat(),"image_base64":base64.b64encode(stream.getvalue()).decode()}
            self.sequence+=1
            return session["session_id"],result
        except Exception:
            self.stop({"session_id":session["session_id"]})
            raise
