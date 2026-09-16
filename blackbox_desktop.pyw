from __future__ import annotations
import json, os, subprocess, sys, threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from blackbox_core.scanner import scan_repo


def apply_style(root):
    style = ttk.Style(root)
    try:
        style.theme_use('clam')
    except tk.TclError:
        pass
    bg = '#0f1318'; panel='#171d24'; panel2='#1d252e'; fg='#edf2f7'; muted='#98a2ad'; accent='#c9f45b'; border='#2b3541'
    root.configure(bg=bg)
    style.configure('.', background=bg, foreground=fg, fieldbackground=panel, font=('Segoe UI', 10))
    style.configure('TFrame', background=bg)
    style.configure('Panel.TFrame', background=panel)
    style.configure('TLabel', background=bg, foreground=fg)
    style.configure('Muted.TLabel', background=bg, foreground=muted)
    style.configure('Title.TLabel', background=bg, foreground=fg, font=('Segoe UI Semibold', 20))
    style.configure('CardValue.TLabel', background=panel, foreground=fg, font=('Segoe UI Semibold', 20))
    style.configure('CardLabel.TLabel', background=panel, foreground=muted, font=('Segoe UI', 9))
    style.configure('TButton', background=panel2, foreground=fg, padding=(11,7), bordercolor=border)
    style.map('TButton', background=[('active', '#26313c')])
    style.configure('Accent.TButton', background=accent, foreground='#111417', padding=(12,7), font=('Segoe UI Semibold',10))
    style.map('Accent.TButton', background=[('active','#d8ff78')])
    style.configure('TEntry', fieldbackground=panel, foreground=fg, insertcolor=fg, bordercolor=border, padding=7)
    style.configure('TCombobox', fieldbackground=panel, background=panel, foreground=fg, arrowcolor=fg, padding=5)
    style.configure('Treeview', background=panel, fieldbackground=panel, foreground=fg, bordercolor=border, rowheight=28)
    style.configure('Treeview.Heading', background=panel2, foreground=fg, font=('Segoe UI Semibold',9), relief='flat')
    style.map('Treeview', background=[('selected','#2b3b48')])
    style.configure('TNotebook', background=bg, borderwidth=0)
    style.configure('TNotebook.Tab', background=panel, foreground=muted, padding=(13,8))
    style.map('TNotebook.Tab', background=[('selected',panel2)], foreground=[('selected',fg)])
    style.configure('Horizontal.TProgressbar', troughcolor=panel, background=accent, bordercolor=panel)
    return {'bg':bg,'panel':panel,'panel2':panel2,'fg':fg,'muted':muted,'accent':accent,'border':border}

def human_bytes(n):
    n = float(n or 0)
    for unit in ('B','KB','MB','GB','TB'):
        if n < 1024 or unit == 'TB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024

def open_path(path):
    path = str(path)
    if sys.platform.startswith('win'):
        os.startfile(path)
    elif sys.platform == 'darwin':
        subprocess.Popen(['open', path])
    else:
        subprocess.Popen(['xdg-open', path])

def reveal_path(path):
    path = str(path)
    if sys.platform.startswith('win'):
        subprocess.Popen(['explorer', '/select,', os.path.normpath(path)])
    elif sys.platform == 'darwin':
        subprocess.Popen(['open', '-R', path])
    else:
        subprocess.Popen(['xdg-open', str(Path(path).parent)])


class BlackboxApp:
    def __init__(self, root):
        self.root = root
        self.colors = apply_style(root)
        root.title('BLACKBOX — Repository Forensics')
        root.geometry('1180x760')
        root.minsize(900, 620)
        self.report = None
        self.repo_root = None
        self.finding_filter = tk.StringVar(value='All')
        self.path_var = tk.StringVar()
        self.status_var = tk.StringVar(value='Choose a repository to begin.')
        self._build()

    def _build(self):
        top = ttk.Frame(self.root, padding=(22,18,22,10)); top.pack(fill='x')
        ttk.Label(top, text='BLACKBOX', style='Title.TLabel').pack(side='left')
        ttk.Label(top, text='Deterministic repository forensics', style='Muted.TLabel').pack(side='left', padx=(14,0), pady=(6,0))
        ttk.Button(top, text='Export JSON', command=self.export_json).pack(side='right')

        chooser = ttk.Frame(self.root, padding=(22,8)); chooser.pack(fill='x')
        ttk.Entry(chooser, textvariable=self.path_var).pack(side='left', fill='x', expand=True)
        ttk.Button(chooser, text='Browse…', command=self.browse).pack(side='left', padx=(8,0))
        ttk.Button(chooser, text='Scan Repository', style='Accent.TButton', command=self.scan).pack(side='left', padx=(8,0))

        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(fill='x', padx=22, pady=(0,8))

        cards = ttk.Frame(self.root, padding=(22,4)); cards.pack(fill='x')
        self.card_vars = {}
        for key, label in [('risk','Overall risk'),('files','Files'),('loc','Lines of code'),('findings','Findings'),('cycles','Cycles')]:
            f = ttk.Frame(cards, style='Panel.TFrame', padding=14); f.pack(side='left', fill='x', expand=True, padx=(0 if key=='risk' else 7,0))
            v = tk.StringVar(value='—'); self.card_vars[key] = v
            ttk.Label(f, textvariable=v, style='CardValue.TLabel').pack(anchor='w')
            ttk.Label(f, text=label, style='CardLabel.TLabel').pack(anchor='w', pady=(3,0))

        self.nb = ttk.Notebook(self.root); self.nb.pack(fill='both', expand=True, padx=22, pady=(12,10))
        self.overview = self._text_tab('Overview')
        self.hotspots_tab = ttk.Frame(self.nb); self.nb.add(self.hotspots_tab, text='Hotspots')
        self.findings_tab = ttk.Frame(self.nb); self.nb.add(self.findings_tab, text='Findings')
        self.deps = self._text_tab('Dependencies')
        self.git = self._text_tab('Git & packages')
        self._build_hotspots(); self._build_findings()

        status = ttk.Frame(self.root, padding=(22,6,22,14)); status.pack(fill='x')
        ttk.Label(status, textvariable=self.status_var, style='Muted.TLabel').pack(side='left')

    def _text_tab(self, title):
        f = ttk.Frame(self.nb); self.nb.add(f, text=title)
        t = tk.Text(f, wrap='word', bg=self.colors['panel'], fg=self.colors['fg'], insertbackground=self.colors['fg'], relief='flat', padx=14, pady=12, font=('Consolas',10))
        t.pack(fill='both', expand=True); t.configure(state='disabled')
        return t

    def _build_hotspots(self):
        cols=('risk','path','loc','complexity','git','inbound','todo')
        self.hotspots = ttk.Treeview(self.hotspots_tab, columns=cols, show='headings')
        heads={'risk':'Risk','path':'Path','loc':'LOC','complexity':'Complexity','git':'Git touches','inbound':'Inbound','todo':'TODO'}
        widths={'risk':75,'path':470,'loc':80,'complexity':95,'git':95,'inbound':80,'todo':65}
        for c in cols:
            self.hotspots.heading(c,text=heads[c]); self.hotspots.column(c,width=widths[c],anchor='w' if c=='path' else 'center')
        y=ttk.Scrollbar(self.hotspots_tab, orient='vertical', command=self.hotspots.yview); self.hotspots.configure(yscrollcommand=y.set)
        self.hotspots.pack(side='left',fill='both',expand=True); y.pack(side='right',fill='y')
        self.hotspots.bind('<Double-1>', lambda e:self.open_selected_hotspot())

    def _build_findings(self):
        tools=ttk.Frame(self.findings_tab,padding=(0,0,0,7)); tools.pack(fill='x')
        ttk.Label(tools,text='Severity:',style='Muted.TLabel').pack(side='left')
        combo=ttk.Combobox(tools,textvariable=self.finding_filter,values=['All','critical','high','medium','low','info'],state='readonly',width=12)
        combo.pack(side='left',padx=(7,0)); combo.bind('<<ComboboxSelected>>',lambda e:self.populate_findings())
        cols=('severity','type','file','line','title')
        self.findings=ttk.Treeview(self.findings_tab,columns=cols,show='headings')
        for c,w in [('severity',90),('type',100),('file',370),('line',65),('title',420)]:
            self.findings.heading(c,text=c.title()); self.findings.column(c,width=w,anchor='w')
        self.findings.pack(fill='both',expand=True)
        self.findings.bind('<<TreeviewSelect>>', self.show_finding_detail)
        self.finding_detail=tk.Text(self.findings_tab,height=4,wrap='word',bg=self.colors['panel'],fg=self.colors['muted'],relief='flat',padx=10,pady=8)
        self.finding_detail.pack(fill='x',pady=(7,0)); self.finding_detail.configure(state='disabled')

    def browse(self):
        p=filedialog.askdirectory(title='Choose repository')
        if p: self.path_var.set(p)

    def scan(self):
        p=self.path_var.get().strip()
        if not p: return self.browse()
        if not Path(p).is_dir():
            messagebox.showerror('BLACKBOX','That path is not a folder.'); return
        self.status_var.set('Scanning repository…'); self.progress.start(12)
        def worker():
            try: report=scan_repo(p); err=None
            except Exception as e: report=None; err=e
            self.root.after(0, lambda:self._scan_done(report,err))
        threading.Thread(target=worker,daemon=True).start()

    def _scan_done(self, report, err):
        self.progress.stop()
        if err:
            self.status_var.set('Scan failed.'); messagebox.showerror('BLACKBOX',str(err)); return
        self.report=report; self.repo_root=Path(report['root'])
        s=report['summary']
        self.card_vars['risk'].set(f"{s['overall_risk']}/100")
        self.card_vars['files'].set(f"{s['files']:,}")
        self.card_vars['loc'].set(f"{s['loc']:,}")
        self.card_vars['findings'].set(f"{s['findings']:,}")
        self.card_vars['cycles'].set(f"{s['cycles']:,}")
        self.populate_all()
        self.status_var.set(f"Scanned {report['project']} — {s['files']:,} files, {s['loc']:,} LOC.")

    def _set_text(self, widget, text):
        widget.configure(state='normal'); widget.delete('1.0','end'); widget.insert('1.0',text); widget.configure(state='disabled')

    def populate_all(self):
        r=self.report
        langs='\n'.join(f"  {x['name']:<14} {x['files']:>6} files" for x in r['languages']) or '  none detected'
        frameworks=', '.join(r['frameworks']) or 'none detected'
        orphans='\n'.join('  '+x for x in r['orphan_candidates'][:30]) or '  none'
        overview=(f"PROJECT\n  {r['project']}\n  {r['root']}\n\nFRAMEWORKS\n  {frameworks}\n\nLANGUAGES\n{langs}\n\nPOSSIBLE ORPHANS\n{orphans}\n")
        self._set_text(self.overview,overview)

        for i in self.hotspots.get_children(): self.hotspots.delete(i)
        for f in r['files'][:1000]:
            self.hotspots.insert('', 'end', values=(f['risk'],f['path'],f['loc'],f['complexity'],f['git_touches'],f['inbound'],f['todo_count']))
        self.populate_findings()

        cyc=[]
        for n,c in enumerate(r['cycles'],1): cyc.append(f"CYCLE {n}\n  "+' -> '.join(c)+"\n")
        edges='\n'.join(f"  {e['source']}  ->  {e['target']}" for e in r['edges'][:500])
        self._set_text(self.deps,("DEPENDENCY CYCLES\n"+(''.join(cyc) if cyc else '  none\n')+"\nEDGES (first 500)\n"+edges))
        g=r.get('git',{})
        imports='\n'.join(f"  {x['name']:<28} {x['count']:>6}" for x in r['external_imports']) or '  none'
        self._set_text(self.git,"GIT\n"+json.dumps(g,indent=2)+"\n\nEXTERNAL IMPORTS\n"+imports)

    def populate_findings(self):
        if not self.report: return
        for i in self.findings.get_children(): self.findings.delete(i)
        wanted=self.finding_filter.get()
        self._finding_rows=[]
        for f in self.report['findings']:
            if wanted!='All' and f['severity']!=wanted: continue
            iid=self.findings.insert('', 'end', values=(f['severity'],f['type'],f['file'],f['line'] or '',f['title']))
            self._finding_rows.append((iid,f))

    def show_finding_detail(self, _=None):
        sel=self.findings.selection()
        if not sel: return
        item=sel[0]; f=next((x for iid,x in self._finding_rows if iid==item),None)
        if not f:return
        self.finding_detail.configure(state='normal'); self.finding_detail.delete('1.0','end'); self.finding_detail.insert('1.0',f.get('detail','')); self.finding_detail.configure(state='disabled')

    def open_selected_hotspot(self):
        sel=self.hotspots.selection()
        if not sel or not self.repo_root:return
        rel=self.hotspots.item(sel[0],'values')[1]; p=self.repo_root/rel
        if p.exists(): open_path(p)

    def export_json(self):
        if not self.report:
            messagebox.showinfo('BLACKBOX','Scan a repository first.'); return
        p=filedialog.asksaveasfilename(title='Export BLACKBOX report',defaultextension='.json',filetypes=[('JSON','*.json')],initialfile=f"{self.report['project']}-blackbox.json")
        if p:
            Path(p).write_text(json.dumps(self.report,indent=2,ensure_ascii=False),encoding='utf-8'); self.status_var.set(f'Exported {p}')

def main():
    root=tk.Tk(); BlackboxApp(root); root.mainloop()
if __name__=='__main__': main()
