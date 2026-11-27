import {buildRule,decodeRule,portValue,ipValue,starterRuleset,parseJsonSafely} from '../nft_gui/api/static/model.js';
import {filterTemplates,templateValues} from '../nft_gui/api/static/templates.js';
let count=0;
function test(name,fn){try{fn();count++;}catch(error){throw Error(name+': '+error.message);}}
function assert(value,message='assertion failed'){if(!value)throw Error(message);}
function equal(a,b){assert(JSON.stringify(a)===JSON.stringify(b),JSON.stringify(a)+' != '+JSON.stringify(b));}
function rejects(fn){let rejected=false;try{fn();}catch{rejected=true;}assert(rejected,'Expected rejection');}
const c={kind:'chain',family:'inet',table:'filter',name:'input',type:'filter',hook:'input',prio:0,policy:'drop'};
test('Port lists and ranges',()=>equal(portValue('22, 80, 8000-8010'),{set:[22,80,{range:[8000,8010]}]}));
test('Ports outside bounds are rejected',()=>{for(const x of ['0','65536','10-2','22,','ssh','1-2-3'])rejects(()=>portValue(x));});
test('IPv4 CIDR',()=>equal(ipValue('192.0.2.0/24'),{family:'ip',value:{prefix:{addr:'192.0.2.0',len:24}}}));
test('IPv4 invalid input',()=>{for(const x of ['999.1.1.1','1.2.3','10.0.0.01','1.2.3.4/33','host.example'])rejects(()=>ipValue(x));});
test('IPv6 normalization boundary',()=>{for(const x of ['::','::1','2001:db8::/32','1:2:3:4:5:6:7:8'])assert(ipValue(x).family==='ip6');});
test('Invalid IPv6 rejected',()=>{for(const x of [':',':::','1::2::3','1:2:3','gg::1','::/129',':1:2:3:4:5:6:7:8','1:2:3:4:5:6:7:8::'])rejects(()=>ipValue(x));});
test('Rule wizard builds TCP source and port conditions',()=>{const r=buildRule({action:'accept',protocol:'tcp',source:'192.0.2.0/24',dport:'22,443',counter:true,comment:'Admin'},c,[]);const d=decodeRule(r);assert(!d.advanced);assert(d.action==='accept'&&d.protocol==='tcp');assert(d.source==='192.0.2.0/24'&&d.dport==='22, 443');});
test('Ports require TCP or UDP',()=>rejects(()=>buildRule({action:'accept',protocol:'icmp',dport:'22'},c,[])));
test('Rule preserves counter state when edited',()=>{const old={expr:[{statement:{counter:{packets:123,bytes:456}}}]};const r=buildRule({action:'drop',counter:true},c,[],old);equal(r.expr[0].statement.counter,{packets:123,bytes:456});});
test('Named address set reference',()=>{const objects=[{kind:'set',family:'inet',table:'filter',name:'clients',type:'ipv4_addr'}];const r=buildRule({action:'accept',source:'@clients'},c,objects);assert(decodeRule(r).source==='@clients');rejects(()=>buildRule({action:'accept',source:'@missing'},c,objects));});
test('Address families must match',()=>rejects(()=>buildRule({action:'accept',source:'192.0.2.1',destination:'2001:db8::1'},c,[])));
test('Unknown expression stays advanced',()=>assert(decodeRule({expr:[{unsupported_expr:{future:{v:1}}}]}).advanced));
test('Unknown nested match field stays advanced',()=>assert(decodeRule({expr:[{statement:{match:{left:{meta:{key:'iifname'}},op:'==',right:'eth0',future:1}}},{statement:{accept:null}}]}).advanced));
test('Unusual statement order stays advanced',()=>assert(decodeRule({expr:[{statement:{counter:null}},{statement:{match:{left:{meta:{key:'iifname'}},op:'==',right:'eth0'}}},{statement:{accept:null}}]}).advanced));
test('Logging and states roundtrip',()=>{const d=decodeRule(buildRule({action:'drop',states:'invalid, new',log:true,logprefix:'blocked: ',counter:true},c,[]));assert(!d.advanced&&d.log&&d.counter&&d.states==='invalid, new'&&d.logprefix==='blocked: ');});
test('Jump destination must be regular',()=>{rejects(()=>buildRule({action:'jump',target:'input'},c,[c]));const other={kind:'chain',family:'inet',table:'filter',name:'allowed'};assert(decodeRule(buildRule({action:'jump',target:'allowed'},c,[other])).target==='allowed');});
test('DNAT carries family address and port',()=>{const r=buildRule({action:'dnat',protocol:'tcp',natAddress:'192.0.2.10',natPort:'8443'},c,[]);equal(r.expr.at(-1).statement.dnat,{addr:'192.0.2.10',family:'ip',port:8443});assert(!decodeRule(r).advanced);});
test('NAT port requires TCP or UDP',()=>rejects(()=>buildRule({action:'dnat',natAddress:'192.0.2.10',natPort:'8443'},c,[])));
test('Desktop template has explicit default policies',()=>{const ir=starterRuleset();assert(ir.objects.filter(x=>x.kind==='chain').length===3);assert(ir.objects.find(x=>x.name==='input').policy==='drop');assert(ir.objects.find(x=>x.name==='output').policy==='accept');assert(ir.objects.filter(x=>x.kind==='rule').every(r=>!decodeRule(r).advanced));});
test('Web and SSH options add only requested services',()=>{const desktop=starterRuleset(),web=starterRuleset(true,true);assert(web.objects.length===desktop.objects.length+2);equal(web.objects.filter(x=>x.kind==='rule').slice(-2).map(r=>decodeRule(r).dport),['80, 443','22']);});
test('Unsafe JSON integer cannot be silently rounded',()=>{rejects(()=>parseJsonSafely('{"bytes":18446744073709551615}'));equal(parseJsonSafely('{"bytes":123456}'),{bytes:123456});});
const catalog=[{id:'ssh',title:'Serveur administré',summary:'SSH privé',category:'Administration',origin:'classique'},{id:'routeur',title:'Réseaux VLAN',summary:'HTTPS entre réseaux',category:'Routage',origin:'formation'}];
test('Template search ignores case and accents',()=>equal(filterTemplates(catalog,'ADMINISTRE ssh').map(t=>t.id),['ssh']));
test('Template search combines category and all words',()=>{equal(filterTemplates(catalog,'reseaux','Routage').map(t=>t.id),['routeur']);equal(filterTemplates(catalog,'SSH','Routage'),[]);});
test('Training templates are searchable by origin',()=>equal(filterTemplates(catalog,'formation').map(t=>t.id),['routeur']));
test('Template form only submits declared parameters and preserves empty input for validation',()=>equal(templateValues({parameters:[{key:'port',default:'22'},{key:'network',default:'192.168.1.0/24'}]},{port:'',arbitrary:'ignored'}),{port:'',network:'192.168.1.0/24'}));
console.log(`${count} frontend model tests passed`);
