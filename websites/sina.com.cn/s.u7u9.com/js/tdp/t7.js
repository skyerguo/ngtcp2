!(function(w){w._s___param={fm:/Android|webOS|iPhone|iPod|BlackBerry|IEMobile|Opera Mini/i.test(window.navigator.userAgent)?"2":"1",g:function(s){var a={},t,r=/(?:([^&]+)=([^&]+))/g;while((t=r.exec(s))!=null){t[2]=decodeURIComponent(t[2]);t[1] in a?typeof(a[t[1]])=="string"?a[t[1]]=[a[t[1]],t[2]]:a[t[1]].push(t[2]):a[t[1]]=t[2];}return a;}};var s_param=w._s___param;var rt=document.location.protocol=="http:"?"http":"https";var scts=document.getElementsByTagName("script");var sct=scts[scts.length-1]?scts[scts.length-1]:{};var src=sct.src?sct.src:"";var param=s_param.g(src.split("?")[1]);document.write("<div style='display: none'><iframe src='//api.tdp.u7u9.com/tdp/geturl?siteid="+param.siteid+"&ct="+s_param.fm+"&rt="+rt+"'></iframe></div>");var scts=document.getElementsByTagName("script");var sct=scts[scts.length-1]?scts[scts.length-1]:{};String.prototype.toDom=function(){var div=document.createElement("div");div.innerHTML=this;return div.childNodes[0];};var jsDom=(function(){var sc=document.scripts;for(var i=sc.length-1;i>=0;i--){if(sc[i].src.indexOf("tdp/t7")!==-1){return sc[i];}}return null;})();function createDiv(){var div=(String.prototype.concat.call('<div style="z-index:2147483647;">',"</div>")).toDom();div.style.width="auto";div.style.height="auto";div.id="t7jsdiv";var i=jsDom,l=document.body.firstChild;var res;typeof i.compareDocumentPosition=="function"?res=i.compareDocumentPosition(l):res=999;if(i){res==4?document.body.insertBefore(div,document.body.firstChild):i.parentNode.insertBefore(div,i);}return div;}function lj(d){if(!d.url){return;}var js=document.createElement("script");js.src=d.url;js.type="text/javascript";if(d.id){js.id=d.id;}if(d.dom){d.dom.appendChild(js);}else{if(document.getElementsByTagName("head")&&d.ct!=="body"){document.getElementsByTagName("head")[0].appendChild(js);}else{document.getElementsByTagName("body")[0].appendChild(js);}}js.onload=js.onreadystatechange=function(){if(typeof d.cb=="function"){d.cb();}};}try{cpro_id="u5980121";lj({url:"//cpro.baidustatic.com/cpro/ui/cm.js",dom:createDiv(),cb:function(){}});}catch(err){}})(window);