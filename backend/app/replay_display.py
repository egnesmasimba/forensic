"""Inert original-layout display. Source bytes remain separately preserved."""
import re
from html import escape
from html.parser import HTMLParser

TAGS={"html","head","body","title","style","div","span","p","br","hr","pre","code","b","strong","i","em","u","small","h1","h2","h3","h4","h5","h6","table","thead","tbody","tfoot","tr","td","th","caption","ul","ol","li","dl","dt","dd","label","form","input","select","option","textarea","button","img","a","section","article","header","footer","main"}
ATTRS={"class","id","style","title","role","aria-label","colspan","rowspan","width","height","type","value","placeholder","checked","selected","disabled"}
SKIP={"script","iframe","object","embed","svg","math","template"}
VOID={"br","hr","input","img"}

class DisplayParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True);self.output=[];self.skip=0;self.nodes=0
    def handle_starttag(self,tag,attrs):
        self.nodes+=1
        if self.nodes>5000:raise ValueError("Display node limit")
        if tag in SKIP:self.skip+=1;return
        if self.skip or tag not in TAGS:return
        clean=[]
        for key,value in attrs:
            value=value or ""
            if key in ATTRS:clean.append((key,value[:4096]))
            elif key=="src" and tag=="img" and re.match(r"^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$",value,re.I):clean.append((key,value))
        if tag in ("input","button","select","textarea"):clean.append(("disabled","disabled"))
        self.output.append("<"+tag+"".join(" "+key+'="'+escape(value,quote=True)+'"' for key,value in clean)+">")
    def handle_startendtag(self,tag,attrs):
        self.handle_starttag(tag,attrs)
        if tag not in VOID:self.handle_endtag(tag)
    def handle_endtag(self,tag):
        if tag in SKIP:
            if self.skip:self.skip-=1
        elif not self.skip and tag in TAGS and tag not in VOID:self.output.append("</"+tag+">")
    def handle_data(self,data):
        if not self.skip:self.output.append(escape(data))

def display_html(source):
    parser=DisplayParser()
    try:parser.feed(source);parser.close();return "".join(parser.output)
    except ValueError:return "<pre>Original layout exceeded display limits. Preserved source:\n"+escape(source)+"</pre>"
