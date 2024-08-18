# Hopper Disassembler script to import comments
# Import comments in the form of {binary}+{hex address) {comment}
import re
import subprocess
from pathlib import Path

doc = Document.getCurrentDocument()

binary_name = Path(doc.getExecutableFilePath()).name

path = Document.askFile('comments', '', False)

count = 0

pattern = re.compile('\\b([.a-zA-Z0-9_-]+)\\+(0x[0-9a-f]+)\\S*\\s+')

with open(path) as file:
	for line in file:
		match = pattern.search(line)
		if match is not None and match[1] == binary_name:
			addr = int(match[2], 0)
			remaining = line[match.end(0):]
			seg = doc.getSegmentAtAddress(addr)
			existing = seg.getInlineCommentAtAddress(addr)
			if existing is None:
				comment = remaining
			else:
				comment = existing + ", " + remaining
			seg.setInlineCommentAtAddress(addr, comment)
			count = count + 1

print(f"imported {count} comments from {path}")
