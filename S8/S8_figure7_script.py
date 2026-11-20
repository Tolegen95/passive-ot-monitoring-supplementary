import csv,collections,sys
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm
from matplotlib.lines import Line2D
plt.rcParams['font.family']='Inter'
M=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
rank={'simulated_or_generated':0,'offline_benchmark':1,'physical_lab':2,'field_pilot':3}
COL={'simulated_or_generated':'#6aaf9c','offline_benchmark':'#8195aa','physical_lab':'#d9a74e','field_pilot':'#4a72a6'}
TXT={'simulated_or_generated':'#111111','offline_benchmark':'#111111','physical_lab':'white','field_pilot':'white'}
cols=['Confirmed off-path capture','Passive-obtainable, capture point unclear','Offline benchmark data','Hybrid architecture']
clab=['Confirmed off-path','Passive-obtainable\npoint unclear','Offline benchmark','Hybrid architecture']
names={'T1692.001':'Unauthorized command','T0814':'Denial of service','T0846':'Remote discovery','T0830':'Adversary-in-middle','T1692.002':'Spoof reporting','T0846.001':'Port scan','T0836':'Modify parameter','T0816':'Device restart/shutdown','T0843':'Program download','T0866':'Exploit remote service','T0886':'Remote services','T0802':'Automated collection','T0806':'Brute force I/O','T0813':'Denial of control','T0815':'Denial of view','T0821':'Modify controller tasking','T0832':'Manipulate view','T0848':'Rogue master','T0859':'Valid accounts','T0867':'Lateral tool transfer','T0869':'Standard app protocol','T0877':'I/O image','T0881':'Service stop','T0888':'Remote system information','T1691.001':'Block command','T1693.001':'System firmware'}
order=list(names)
C=collections.defaultdict(list); rep=collections.Counter()
for r in M:
    for t in r['attck_ics_techniques_v20_1'].split(';'):
        if t: C[(t,r['observation_evidence'])].append(r)
assert set(t for t,_ in C)==set(order), set(t for t,_ in C)^set(order)
fig,ax=plt.subplots(figsize=(7.32,7.33),dpi=300)
fig.subplots_adjust(left=0.29,right=0.985,top=0.955,bottom=0.175)
ax.set_facecolor('#fafbfb')
for i in range(len(order)+1): ax.axhline(i-0.5,color='#d5dbe1',lw=0.6,zorder=0)
for j in range(5): ax.axvline(j-0.5,color='#d5dbe1',lw=0.6,zorder=0)
for (t,o),v in C.items():
    x=cols.index(o); y=order.index(t); n=len(v)
    h=sum(int(r['n_high_quadas_domains'])>0 for r in v); a=any('author' in r['mapping_basis'] for r in v)
    top=max(v,key=lambda r:rank[r['evaluation_setting']])['evaluation_setting']
    s=230+105*(n-1)
    ax.scatter(x,y,s=s,c=COL[top],edgecolors='#1f2937' if h else 'white',linewidths=1.8 if h else 0.8,zorder=3)
    ax.text(x,y,f"{n}{f'[{h}]' if h else ''}{'*' if a else ''}",ha='center',va='center',fontsize=6.2,fontweight='semibold',color=TXT[top],zorder=4)
ax.set_xlim(-0.5,3.5); ax.set_ylim(len(order)-0.5,-0.5)
ax.set_yticks(range(len(order))); ax.set_yticklabels([f'{t}  {names[t]}' for t in order],fontsize=7.3)
ax.set_xticks(range(4)); ax.set_xticklabels(clab,fontsize=7.6)
for s_ in ax.spines.values(): s_.set_visible(False)
ax.set_ylabel('Candidate ATT&CK technique mapping',fontsize=9)
ax.set_title(f'ATT&CK for ICS evidence map: {len(order)} of 104 v20.1 techniques; {len(M)} reports',fontsize=9.6,pad=4)
L=[Line2D([0],[0],marker='o',ls='',markersize=7,markerfacecolor=COL[k],markeredgecolor='white',label=l) for k,l in [('offline_benchmark','Offline benchmark'),('simulated_or_generated','Simulated/generated'),('physical_lab','Physical laboratory'),('field_pilot','Field pilot')]]
L.append(Line2D([0],[0],marker='o',ls='',markersize=7,markerfacecolor='#d5dbe1',markeredgecolor='#1f2937',markeredgewidth=2,label='≥1 High-risk domain in cell'))
fig.legend(handles=L,loc='lower center',bbox_to_anchor=(0.62,0.018),ncol=3,frameon=False,fontsize=7.6,title='Colour = highest evaluation setting in cell',title_fontsize=7.6)
fig.text(0.01,0.006,'Label = reports in cell; [n] = reports with ≥1 High QUADAS-2-OT domain; * = includes an author-assigned mapping (others reviewer-inferred). Empty cell = no mapped report.',fontsize=5.6,color='#374151')
fig.savefig(sys.argv[2],dpi=300,facecolor='white')
