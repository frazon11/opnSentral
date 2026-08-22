(function(){
    'use strict';

    const storageKey='opnsentral-presentation-mode';
    const legacyStorageKey='opncentral-presentation-mode';
    const mappingKey='opnsentral-presentation-mapping-v2';

    if(localStorage.getItem(storageKey)===null && localStorage.getItem(legacyStorageKey)!==null){
        localStorage.setItem(storageKey,localStorage.getItem(legacyStorageKey));
        localStorage.removeItem(legacyStorageKey);
    }

    let enabled=localStorage.getItem(storageKey)==='1';
    let mappings=loadMappings();
    let observer=null;
    let applying=false;
    const originalTextValues=new WeakMap();
    const originalAttributeValues=new WeakMap();

    function loadMappings(){
        try{
            const parsed=JSON.parse(sessionStorage.getItem(mappingKey)||'{}');
            return parsed&&typeof parsed==='object'?parsed:{};
        }catch(error){return {};}
    }
    function saveMappings(){sessionStorage.setItem(mappingKey,JSON.stringify(mappings));}
    function hashString(value){let hash=2166136261;for(let i=0;i<value.length;i++){hash^=value.charCodeAt(i);hash=Math.imul(hash,16777619);}return hash>>>0;}
    function stableNumber(value,min,max){return min+(hashString(value)%(max-min+1));}
    function mapped(category,original,producer){const key=category+':'+original;if(!Object.prototype.hasOwnProperty.call(mappings,key)){mappings[key]=producer();saveMappings();}return mappings[key];}
    function fakeName(original){
        return mapped('name-v2',original,function(){
            const chars=Array.from(String(original));
            if(chars.length<=2)return String(original);
            const vowels='aeiou';
            const consonants='bcdfghjklmnpqrstvwxyz';
            let middle='';
            for(let i=1;i<chars.length-1;i++){
                const source=chars[i];
                const pool=i%2===0?vowels:consonants;
                let replacement=pool[stableNumber(original+':'+i,0,pool.length-1)];
                if(/[A-Z]/.test(source))replacement=replacement.toUpperCase();
                middle+=replacement;
            }
            return chars[0]+middle+chars[chars.length-1];
        });
    }
    function anonymizeIpv4(address){return mapped('ipv4',address,function(){const p=address.split('.').map(Number);if(p.length!==4)return '192.0.2.'+stableNumber(address,1,254);if(p[0]===10)return [10,stableNumber(address+':b',1,254),stableNumber(address+':c',1,254),stableNumber(address+':d',1,254)].join('.');if(p[0]===172&&p[1]>=16&&p[1]<=31)return [172,stableNumber(address+':b',16,31),stableNumber(address+':c',1,254),stableNumber(address+':d',1,254)].join('.');if(p[0]===192&&p[1]===168)return [192,168,stableNumber(address+':c',1,254),stableNumber(address+':d',1,254)].join('.');return [192,0,2,stableNumber(address,1,254)].join('.');});}
    function anonymizeIpv6(address){return mapped('ipv6',address,function(){const a=stableNumber(address+':a',1,65535).toString(16);const b=stableNumber(address+':b',1,65535).toString(16);const c=stableNumber(address+':c',1,65535).toString(16);return '2001:db8:'+a+':'+b+'::'+c;});}
    function anonymizeEmail(email){return mapped('email',email,()=> 'user'+stableNumber(email,1,999)+'@example.invalid');}
    function anonymizeHost(host){return mapped('host',host,function(){const lower=host.toLowerCase();if(lower==='localhost')return 'demo-host.local';const suffix=lower.endsWith('.local')?'.demo.local':'.example.invalid';return 'host-'+stableNumber(host,1,999)+suffix;});}
    function presentationNames(){
        const names=Array.isArray(window.opnSentralPresentationNames)?window.opnSentralPresentationNames:[];
        return Array.from(new Set(names.map(value=>String(value||'').trim()).filter(Boolean)));
    }
    function registerNames(values){
        if(!Array.isArray(window.opnSentralPresentationNames))window.opnSentralPresentationNames=[];
        const current=new Set(window.opnSentralPresentationNames.map(value=>String(value)));
        (Array.isArray(values)?values:[values]).forEach(function(value){const name=String(value||'').trim();if(name&&!current.has(name)){window.opnSentralPresentationNames.push(name);current.add(name);}});
        if(enabled)apply();
    }
    function replaceVisibleText(input){
        let output=String(input);
        presentationNames().slice().sort((a,b)=>b.length-a.length).forEach(function(name){if(name)output=output.split(name).join(fakeName(name));});
        output=output.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,anonymizeEmail);
        output=output.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,anonymizeIpv4);
        output=output.replace(/\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{0,4}\b/gi,anonymizeIpv6);
        output=output.replace(/\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\b/gi,function(match){const pm=match.match(/^https?:\/\//i);const protocol=pm?pm[0]:'';const rest=match.slice(protocol.length);const portMatch=rest.match(/:\d+$/);const port=portMatch?portMatch[0]:'';const host=port?rest.slice(0,-port.length):rest;return protocol+anonymizeHost(host)+port;});
        return output;
    }
    function shouldSkip(node){const parent=node.parentElement;if(!parent)return true;return Boolean(parent.closest('script,style,noscript,template,[data-presentation-exempt="true"],.presentation-mode-stack,.configuration-unlock-dialog'));}
    function transformTextNode(node){if(shouldSkip(node))return;if(!originalTextValues.has(node))originalTextValues.set(node,node.nodeValue||'');const original=originalTextValues.get(node)||'';const replacement=replaceVisibleText(original);if(node.nodeValue!==replacement)node.nodeValue=replacement;}
    function restoreTextNode(node){if(!originalTextValues.has(node))return;const original=originalTextValues.get(node)||'';if(node.nodeValue!==original)node.nodeValue=original;originalTextValues.delete(node);}
    function transformElementAttributes(element){const attrs=['title','aria-label','placeholder'];let originals=originalAttributeValues.get(element);if(!originals){originals={};originalAttributeValues.set(element,originals);}attrs.forEach(function(attr){if(!element.hasAttribute(attr))return;if(!Object.prototype.hasOwnProperty.call(originals,attr))originals[attr]=element.getAttribute(attr);element.setAttribute(attr,replaceVisibleText(originals[attr]||''));});}
    function restoreElementAttributes(element){const originals=originalAttributeValues.get(element);if(!originals)return;Object.entries(originals).forEach(([attr,value])=>value===null?element.removeAttribute(attr):element.setAttribute(attr,value));originalAttributeValues.delete(element);}
    function walk(root,transform){
        if(root.nodeType===Node.TEXT_NODE){transform?transformTextNode(root):restoreTextNode(root);return;}
        if(root.nodeType!==Node.ELEMENT_NODE&&root.nodeType!==Node.DOCUMENT_NODE&&root.nodeType!==Node.DOCUMENT_FRAGMENT_NODE)return;
        if(root.nodeType===Node.ELEMENT_NODE){if(root.closest('[data-presentation-exempt="true"],.presentation-mode-stack'))return;transform?transformElementAttributes(root):restoreElementAttributes(root);}
        const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT|NodeFilter.SHOW_ELEMENT);let current;
        while((current=walker.nextNode())){if(current.nodeType===Node.TEXT_NODE){transform?transformTextNode(current):restoreTextNode(current);}else{transform?transformElementAttributes(current):restoreElementAttributes(current);}}
    }
    function startObserver(){if(observer)return;observer=new MutationObserver(function(mutations){if(!enabled||applying)return;applying=true;try{mutations.forEach(function(mutation){mutation.addedNodes.forEach(node=>walk(node,true));if(mutation.type==='characterData'&&mutation.target.nodeType===Node.TEXT_NODE)transformTextNode(mutation.target);});}finally{applying=false;}});observer.observe(document.body,{childList:true,subtree:true,characterData:true});}
    function stopObserver(){if(observer){observer.disconnect();observer=null;}}
    function updateUi(){document.body.classList.toggle('presentation-mode',enabled);}
    function apply(){applying=true;try{if(enabled){walk(document.body,true);startObserver();}else{stopObserver();walk(document.body,false);}updateUi();}finally{applying=false;}}

    window.opnSentralApplyPresentationMode=apply;
    window.opnSentralPresentationEnabled=()=>enabled;
    window.opnSentralRegisterPresentationNames=registerNames;
    window.opnSentralSetPresentationMode=function(value){enabled=Boolean(value);localStorage.setItem(storageKey,enabled?'1':'0');apply();};

    if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',apply,{once:true});else apply();
})();
