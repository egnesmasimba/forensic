package main
import ("strings"; "testing")
func TestSummary(t *testing.T) {
 got,err:=summarize(strings.NewReader(`{"metrics":{},"sessions":[{"protocol":"HTTP","payload_bytes":4},{"protocol":"HTTP","payload_bytes":7}]}`))
 if err!=nil || got["HTTP"].Bytes!=11 || got["HTTP"].Sessions!=2 { t.Fatalf("%v %v",got,err) }
 for _, input:=range []string{`{}`,`{"metrics":{},"sessions":[]} trailing`,`{"metrics":{},"sessions":[{"payload_bytes":-1}]}`,`{"metrics":{},"sessions":[{"payload_bytes":18446744073709551615},{"payload_bytes":1}]}`} {
  if _,err:=summarize(strings.NewReader(input)); err==nil { t.Fatalf("accepted invalid input %s",input) }
 }
}

func TestReportBounds(t *testing.T) {
 if _,err:=summarize(strings.NewReader(strings.Repeat(" ",maxReport+1))); err==nil { t.Fatal("accepted oversized report") }
 got,err:=summarize(strings.NewReader(`{"metrics":{},"sessions":[]}`))
 if err!=nil || len(got)!=0 { t.Fatalf("empty report: %v %v",got,err) }
 got,err=summarize(strings.NewReader(`{"metrics":{},"sessions":[{"payload_bytes":3}]}`))
 if err!=nil || got["unknown"].Bytes!=3 { t.Fatalf("unknown protocol: %v %v",got,err) }
}
