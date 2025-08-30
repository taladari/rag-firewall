# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Tal Adari

import argparse, os, glob
from rag_firewall import Firewall
from rag_firewall.provenance import Hasher, ProvenanceStore
from rag_firewall.audit import Audit

def cmd_index(args):
    store=ProvenanceStore(args.store); files=glob.glob(os.path.join(args.path,'**/*'), recursive=True); count=0
    for f in files:
        if os.path.isdir(f): continue
        try:
            text=open(f,'r',encoding='utf-8').read()
            h=Hasher.hash_text(text); store.record(hash=h, source=args.source, sensitivity=args.sensitivity); count+=1
        except Exception: pass
    print(f'Indexed {count} files into {args.store}')

def cmd_query(args):
    fw=Firewall.from_yaml(args.config); docs=[]
    for f in glob.glob(os.path.join(args.docs,'**/*'), recursive=True):
        if os.path.isdir(f): continue
        try:
            text=open(f,'r',encoding='utf-8').read()
            docs.append({'page_content':text,'metadata':{'source':f,'hash':Hasher.hash_text(text)}})
        except Exception: pass
    safe=[]
    for d in docs:
        dec, findings = fw.decide(d, base_score=1.0, context={'query':args.query})
        if dec.get('action')!='deny': safe.append(d)
        if args.show_decisions: print(dec)
    print(f'Safe docs: {len(safe)} / {len(docs)}')
    for ev in Audit.tail(10): print(ev)

def main():
    p=argparse.ArgumentParser('ragfw'); sub=p.add_subparsers(dest='cmd')
    p1=sub.add_parser('index'); p1.add_argument('path'); p1.add_argument('--store',default='prov.sqlite'); p1.add_argument('--source',default='uploads'); p1.add_argument('--sensitivity',default='low'); p1.set_defaults(func=cmd_index)
    p2=sub.add_parser('query'); p2.add_argument('query'); p2.add_argument('--docs',default='./docs'); p2.add_argument('--config',default='firewall.yaml'); p2.add_argument('--store',default='prov.sqlite'); p2.add_argument('--show-decisions',action='store_true'); p2.set_defaults(func=cmd_query)
    args=p.parse_args(); 
    if not hasattr(args,'func'): p.print_help(); return
    args.func(args)

if __name__=='__main__': main()
