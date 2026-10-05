"""Bounded, non-executing extraction of supplied HTML and terminal text."""
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser


MAX_CONTENT = 262144
HIDDEN = {"script", "style", "template", "noscript", "head"}
VOID = {"input", "br", "hr", "img", "meta", "link", "area", "base", "embed", "source", "wbr", "param", "col"}


@dataclass
class Node:
    tag: str
    attrs: dict = field(default_factory=dict)
    children: list = field(default_factory=list)


def text(node):
    if isinstance(node, str):
        return node
    if node.tag in HIDDEN or "hidden" in node.attrs or node.attrs.get("aria-hidden") == "true":
        return ""
    return " ".join(text(child) for child in node.children)


def clean(value):
    return " ".join(value.split())


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("root")
        self.stack = [self.root]
        self.nodes = []

    def handle_starttag(self, tag, attrs):
        if len(self.nodes) >= 20000 or len(self.stack) >= 100:
            raise ValueError("Webpage structure exceeds parser limits")
        node = Node(tag, dict(attrs))
        self.stack[-1].children.append(node)
        self.nodes.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def parse_content(content, kind, title=""):
    if len(content) > MAX_CONTENT:
        raise ValueError("Content exceeds 262,144 characters")
    fields, headers = [], []
    if kind == "html":
        parser = PageParser()
        parser.feed(content)
        # Exclude descendants of hidden elements as well as the elements themselves.
        visible = []
        def walk(node, hidden=False):
            if isinstance(node, str):
                return
            hidden |= node.tag in HIDDEN or "hidden" in node.attrs or node.attrs.get("aria-hidden") == "true"
            if not hidden:
                visible.append(node)
            for child in node.children:
                walk(child, hidden)
        walk(parser.root)
        titles = [clean(" ".join(text(c) for c in n.children)) for n in parser.nodes if n.tag == "title"]
        title = title or next((t for t in titles if t), "Webpage")
        labels = {n.attrs["for"]: clean(text(n)) for n in visible if n.tag == "label" and n.attrs.get("for")}
        nested_labels = {}
        def label_text(node):
            if isinstance(node, str):
                return node
            if node.tag in ("input", "textarea", "select"):
                return ""
            return " ".join(label_text(c) for c in node.children)
        def controls(node, caption):
            if isinstance(node, Node):
                if node.tag in ("input", "textarea", "select"):
                    nested_labels[id(node)] = caption
                for child in node.children:
                    controls(child, caption)
        for n in visible:
            if n.tag == "label":
                controls(n, clean(label_text(n)))
        for node in visible:
            if node.tag in ("h1", "h2", "h3", "h4", "h5", "h6", "th", "legend"):
                caption = clean(text(node))
                if caption:
                    headers.append(caption)
            if node.tag not in ("input", "textarea", "select"):
                continue
            a = node.attrs
            input_type = (a.get("type") or "text").lower()
            if input_type in ("password", "hidden", "submit", "reset", "button", "file", "image"):
                continue
            if input_type in ("checkbox", "radio") and "checked" not in a:
                continue
            caption = labels.get(a.get("id")) or nested_labels.get(id(node)) or a.get("aria-label") or a.get("placeholder") or a.get("name") or a.get("id") or "Field"
            value = a.get("value") or ("on" if input_type in ("checkbox", "radio") else "")
            if node.tag == "textarea":
                value = clean(text(node))
            elif node.tag == "select":
                options = [c for c in node.children if isinstance(c, Node) and c.tag == "option"]
                selected = [c for c in options if "selected" in c.attrs]
                if not selected and "multiple" not in a:
                    selected = options[:1]
                value = " ".join(clean(text(c)) for c in selected)
            fields.append({"caption": clean(caption)[:200], "value": str(value)[:4096]})
        body = clean(text(parser.root))
    else:
        # Screen text is an already reconstructed snapshot, not raw escape sequences.
        body = content
        lines = [clean(line) for line in content.splitlines() if line.strip()]
        title = title or (lines[0][:200] if lines else "Screen")
        headers = lines[:1]
        for line in content.splitlines():
            for match in re.finditer(r"(?:^|\s{2,})([\w][\w /().-]{0,100}?)\s*[:=]\s*([^\n]*?)(?=\s{2,}[\w /().-]+\s*[:=]|$)", line):
                fields.append({"caption": clean(match[1]), "value": clean(match[2])[:4096]})
    return {"title": title[:200], "headers": list(dict.fromkeys(headers))[:200],
            "fields": fields[:200], "body": body[:MAX_CONTENT],
            "partial": len(headers) > 200 or len(fields) > 200}
