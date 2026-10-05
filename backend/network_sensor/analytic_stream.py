"""Bridge bounded live sensor summaries into authenticated analytic observations."""
import hashlib
import uuid


class AnalyticSink:
    def __init__(self, client, subject):
        self.client=client; self.subject=subject; self.epoch=uuid.uuid4().hex; self.previous={}; self.seen=set()

    def publish(self, report):
        events=[]
        for session in report['sessions']:
            sid=session['id']; current=(session['packets'],session.get('payload_bytes',0))
            before=self.previous.get(sid,(0,0))
            for name,index in [('network_packets',0),('network_payload_bytes',1)]:
                delta=current[index]-before[index]
                if delta>0:
                    key=hashlib.sha256(f'{self.epoch}:{sid}:{name}:{current[index]}'.encode()).hexdigest()
                    events.append({'type':'analytic_fact','severity':'low','event_key':key,'payload':{'entity_type':'user','entity_ref':self.subject,'name':name,'numeric_value':delta,'text_value':session['protocol']}})
            self.previous[sid]=current
        mapping={'unusual_protocol':'unknown_protocol','malware_callback':'malware_callback','c2':'c2_indicator','network_threat':'port_scan'}
        for finding in report.get('traffic_analysis',{}).get('findings',[]):
            import json
            key=hashlib.sha256(json.dumps([self.epoch,finding],sort_keys=True).encode()).hexdigest()
            if key in self.seen: continue
            signal=mapping.get(finding['category'])
            if finding['title']=='Conflicting TCP overlap': signal='tcp_overlap'
            elif 'periodic' in finding['title'].lower(): signal='periodic_beacon'
            elif finding['category']=='unusual_protocol' and finding['evidence'].get('protocol')!='unknown': signal='protocol_port_mismatch'
            if not signal: continue
            events.append({'type':'analytic_fact','severity':'medium','event_key':key,'payload':{'entity_type':'user','entity_ref':self.subject,'name':signal,'numeric_value':1,'text_value':','.join(finding['session_ids'])[:200]}})
            self.seen.add(key)
        for offset in range(0,len(events),100): self.client.post_events(events[offset:offset+100])
        live={session['id'] for session in report['sessions']}
        self.previous={key:value for key,value in self.previous.items() if key in live}
        # A capture is bounded by the CLI duration; this also caps heuristic state.
        if len(self.seen)>10000: self.seen=set(list(self.seen)[-5000:])
        return len(events)
