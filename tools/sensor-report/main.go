// sensor-report summarizes the Python sensor's sessions.json without exposing endpoints.
package main

import (
 "encoding/json"
 "fmt"
 "io"
 "os"
)

const maxReport = 32 << 20
type Session struct { Protocol string `json:"protocol"`; Bytes uint64 `json:"payload_bytes"` }
type Report struct { Metrics map[string]json.RawMessage `json:"metrics"`; Sessions []Session `json:"sessions"` }
type Total struct { Sessions uint64 `json:"sessions"`; Bytes uint64 `json:"payload_bytes"` }

func summarize(r io.Reader) (map[string]Total, error) {
 data, err := io.ReadAll(io.LimitReader(r, maxReport+1))
 if err != nil { return nil, err }
 if len(data)>maxReport { return nil, fmt.Errorf("report exceeds 32 MiB") }
 var report Report
 if err=json.Unmarshal(data,&report); err!=nil { return nil, err }
 if report.Metrics==nil || report.Sessions==nil { return nil, fmt.Errorf("expected sensor metrics and sessions") }
 totals:=map[string]Total{}
 for _, s:=range report.Sessions {
  key:=s.Protocol; if key=="" { key="unknown" }
  t:=totals[key]
  if ^uint64(0)-t.Bytes<s.Bytes { return nil, fmt.Errorf("payload total overflow") }
  t.Sessions++; t.Bytes+=s.Bytes; totals[key]=t
 }
 return totals,nil
}
func main() {
 if len(os.Args)!=2 { fmt.Fprintln(os.Stderr,"usage: sensor-report sessions.json"); os.Exit(2) }
 file,err:=os.Open(os.Args[1]); if err!=nil { fmt.Fprintln(os.Stderr,err); os.Exit(1) }; defer file.Close()
 totals,err:=summarize(file); if err!=nil { fmt.Fprintln(os.Stderr,err); os.Exit(1) }
 if err=json.NewEncoder(os.Stdout).Encode(totals); err!=nil { os.Exit(1) }
}
