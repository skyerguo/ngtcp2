!function(e,t){"use strict";e=e&&Object.prototype.hasOwnProperty.call(e,"default")?e.default:e,t=t&&Object.prototype.hasOwnProperty.call(t,"default")?t.default:t;var n=document,o=t.util.merge,i=e.switches,a=1e3*i.upAdOnTabTimeout,r=!1,u=function(o){var i=t.dom.createElement('<i class="zeropixel"></i>');n.body.appendChild(i),e.Block.waitFor("ad").then((function(e){e.constructor.insertByHtml(i,o),setTimeout((function(){t.dom.killElement(i)}),6e4)}))},c=function(){return e.Block.waitFor("ad").then((function(e){return e.updateAds(e.slotHandlers)})).then((function(){e.counter("d1464827")}))};e._.STUCK_IN_POT||e.Block.waitFor("ad").then((function(e){o(e.slotHandlers,{4015:u,217:u})})),i.upAdOnTabTimeout&&n.addEventListener("visibilitychange",(function(){var e=!n.hidden;e&&r&&c(),e||(r=!1,setTimeout((function(){r=!0}),a))})),window.__PH.on("authChange",(function(e,t){i.upAdOnAuthChange&&c(),t()})),i.updateAdOnTab&&e.Block.waitFor("tabs").then((function(e){e.on("switch",c)}));var d=t.util,l=(d.each,d.merge),s=(d.arrayPush,e._),m=s.PREVIEW,f=s.AUTH,h=(s.EMAIL,document);t.transport("?json=1"+(m?"&preview="+m:""),{json:!0});setTimeout((function(){}),60*(f?1:2)*1e3),l(e,{refresh:function(e){}}),h.addEventListener("visibilitychange",(function(){}));var T=$.dom.id,p=function(){var e=new Date(Date.now()+mr._.TIMESTAMP_DELTA),t=new Date(e.getTime()+60*e.getTimezoneOffset()*1e3+1e3*mr._.TIMEZONE).getDate(),n=T("cal");n&&(n.innerHTML=t),setTimeout(p,1e3*(59-e.getSeconds())+1e3-e.getMilliseconds())};$.util.extend(mr,{calendar:p}),mr.calendar(),window.mr=mr}(mr,$);
