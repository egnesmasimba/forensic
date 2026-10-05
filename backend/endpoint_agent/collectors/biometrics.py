"""Aggregate input timing and relative movement; never serialize keys or positions."""
from collections import deque
from statistics import mean, pstdev
import math
import threading
import time
from . import Collector
from ..biometric_capture import permitted


class BiometricCollector(Collector):
    name = 'biometrics'
    sensitive = True
    requires = ('pynput',)
    default_interval_seconds = 10.0

    def __init__(self, config=None):
        super().__init__(config)
        self.lock=threading.Lock(); self.listeners=[]
        self.held={}; self.pending_flights={}; self.released={}; self.last_key=None; self.last_press=None; self.last_release=None; self.last_mouse=None; self.last_vector=None
        self.holds=deque(maxlen=512); self.intervals=deque(maxlen=512); self.flights=deque(maxlen=512)
        self.speeds=deque(maxlen=512); self.turns=deque(maxlen=512)
        self.keys=self.moves=0; self.started=time.monotonic()

    @classmethod
    def supports_current_os(cls):
        try:
            import pynput
            return True
        except Exception: return False

    def press(self, key, stamp=None):
        if not permitted(): return
        now=time.monotonic() if stamp is None else stamp
        with self.lock:
            if key in self.held or len(self.held)>=256: return
            self.keys+=1
            if self.last_press is not None and 0<=now-self.last_press<=10: self.intervals.append((now-self.last_press)*1000)
            if self.last_key in self.held:
                self.pending_flights[self.last_key]=now
            elif self.last_key in self.released and 0<=now-self.released[self.last_key]<=10:
                self.flights.append((now-self.released[self.last_key])*1000)
            self.held[key]=now
            self.last_key=key
            self.last_press=now

    def release(self,key,stamp=None):
        if not permitted(): return
        now=time.monotonic() if stamp is None else stamp
        with self.lock:
            down=self.held.pop(key,None)
            if down is not None and 0<=now-down<=10: self.holds.append((now-down)*1000)
            next_down=self.pending_flights.pop(key,None)
            if next_down is not None and -10<=next_down-now<=10: self.flights.append((next_down-now)*1000)
            if len(self.released)<256: self.released[key]=now
            self.last_release=now

    def move(self,x,y,stamp=None):
        if not permitted(): return
        now=time.monotonic() if stamp is None else stamp
        with self.lock:
            self.moves+=1
            if self.last_mouse:
                px,py,pt=self.last_mouse; dx=x-px; dy=y-py; dt=now-pt; length=math.hypot(dx,dy)
                if dt>0 and length>0:
                    self.speeds.append(min(100000,length/dt))
                    if self.last_vector:
                        vx,vy=self.last_vector; size=math.hypot(vx,vy)*length
                        if size: self.turns.append(math.acos(max(-1,min(1,(vx*dx+vy*dy)/size))))
                    self.last_vector=(dx,dy)
            self.last_mouse=(x,y,now)

    def snapshot(self, stamp=None):
        now=time.monotonic() if stamp is None else stamp
        average=lambda items: mean(items) if items else 0
        deviation=lambda items: pstdev(items) if items else 0
        with self.lock:
            payload={'key_count':self.keys,'mouse_count':self.moves,'duration_seconds':max(.001,min(3600,now-self.started)),
                     'hold_mean_ms':average(self.holds),'hold_sd_ms':deviation(self.holds),
                     'interval_mean_ms':average(self.intervals),'interval_sd_ms':deviation(self.intervals),
                     'flight_mean_ms':average(self.flights),'mouse_speed_mean':average(self.speeds),'mouse_turn_mean':average(self.turns)}
            for samples in (self.holds,self.intervals,self.flights,self.speeds,self.turns): samples.clear()
            self.held.clear(); self.pending_flights.clear(); self.released.clear(); self.last_key=None
            self.last_mouse=self.last_vector=self.last_press=self.last_release=None
            self.keys=self.moves=0; self.started=now
        return {'type':'behavioral_biometrics','severity':'low','payload':payload}

    def _stop_hooks(self):
        for listener in self.listeners: listener.stop()
        self.listeners=[]
        self.snapshot()

    def _collect(self):
        if not permitted():
            self._stop_hooks(); return []
        if not self.listeners:
            from pynput import keyboard, mouse
            self.listeners=[keyboard.Listener(on_press=lambda key: self.press(key),on_release=lambda key: self.release(key)), mouse.Listener(on_move=lambda x,y: self.move(x,y))]
            for listener in self.listeners: listener.start()
            self.started=time.monotonic(); return []
        event=self.snapshot()
        return [event] if event['payload']['key_count'] or event['payload']['mouse_count'] else []

    def stop(self):
        self._stop_hooks(); super().stop()
