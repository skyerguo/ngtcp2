!function(t,e){"object"==typeof exports&&"object"==typeof module?module.exports=e():"function"==typeof define&&define.amd?define("wafer-action",[],e):"object"==typeof exports?exports["wafer-action"]=e():(t.wafer=t.wafer||{},t.wafer.wafers=t.wafer.wafers||{},t.wafer.wafers["wafer-action"]=e())}("undefined"!=typeof self?self:this,function(){return function(t){function e(n){if(o[n])return o[n].exports;var r=o[n]={i:n,l:!1,exports:{}};return t[n].call(r.exports,r,r.exports,e),r.l=!0,r.exports}var o={};return e.m=t,e.c=o,e.d=function(t,o,n){e.o(t,o)||Object.defineProperty(t,o,{configurable:!1,enumerable:!0,get:n})},e.n=function(t){var o=t&&t.__esModule?function(){return t.default}:function(){return t};return e.d(o,"a",o),o},e.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)},e.p="https://s.yimg.com/aaq/wf/",e(e.s="./src/entry.js")}({"./src/entry.js":function(t,e,o){"use strict";function n(t,e,o){return e in t?Object.defineProperty(t,e,{value:o,enumerable:!0,configurable:!0,writable:!0}):t[e]=o,t}function r(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function i(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}function a(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}function s(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function c(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}function u(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}Object.defineProperty(e,"__esModule",{value:!0});var l="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},f=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var o=arguments[e];for(var n in o)Object.prototype.hasOwnProperty.call(o,n)&&(t[n]=o[n])}return t},p=function(){function t(t,e){var o=[],n=!0,r=!1,i=void 0;try{for(var a,s=t[Symbol.iterator]();!(n=(a=s.next()).done)&&(o.push(a.value),!e||o.length!==e);n=!0);}catch(t){r=!0,i=t}finally{try{!n&&s.return&&s.return()}finally{if(r)throw i}}return o}return function(e,o){if(Array.isArray(e))return e;if(Symbol.iterator in Object(e))return t(e,o);throw new TypeError("Invalid attempt to destructure non-iterable instance")}}(),d=function(){function t(t,e){for(var o=0;o<e.length;o++){var n=e[o];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,o,n){return o&&t(e.prototype,o),n&&t(e,n),e}}(),b=[],y=window.wafer,h=y.constants,v=y.features,m=y.utils,g=y.WaferBaseClass,w=m.fetchWithCache,_=h.ATTR_PREFIX,S=["handleClick"],O="wafer-action-is-true",T={block:-1,unblock:0},j=void 0,P="publisher",A=function(t){function e(t){var o=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},n=o.appId,a=o.actionHost,s=o.crumb,c=o.id,u=o.name,l=o.selector,d=o.shouldSaveToStorage,y=o.subType,h=o.type;r(this,e);var v=i(this,(e.__proto__||Object.getPrototypeOf(e)).call(this,t,{selector:l},{STATE_ATTRS:b}));n=t.getAttribute(_+"app-id")||n,s=t.getAttribute(_+"crumb")||s;var m=t.getAttribute(_+"action-type")||h||"follow",g=t.getAttribute(_+"action-sub-type")||y,w=t.getAttribute(_+"action-id")||c,T=t.getAttribute(_+"action-label"),j=t.getAttribute(_+"action-name")||u,A=T&&T.split("|")||[],k=p(A,2),E=k[0],I=k[1],C={follow:a+"api/v3/topics?appId="+n,block:a+"api/v1/content/feedback/"+(g===P?P:"entities")+"?appId="+n},L=C[m];return v._util=f({},v._util,{actionHost:a,apiPath:L,appId:n,crumb:s,elem:t,falseLabel:I,id:w,mappingId:w+m+g,shouldSaveToStorage:void 0===d?void 0:!!d,name:j,subType:g,trueLabel:E,type:m}),S.forEach(function(t){v[t]=v[t].bind(v)}),v._state={actionStatus:!1,inProgress:!1},t.classList.add("has-click"),setTimeout(function(){v.setActionStatus(t.classList.contains(O))},0),v}return a(e,t),d(e,[{key:"statusDidUpdate",value:function(t){var e=this._util.elem;if(e){var o=this._util,n=o.falseLabel,r=o.trueLabel;this._state.actionStatus=t,t?(n&&e.setAttribute("title",n),e.classList.add(O)):(r&&e.setAttribute("title",r),e.classList.remove(O))}}},{key:"saveToStorage",value:function(){if(v.localStorage){var t=this._util,o=t.id,n=t.name,r=void 0===n?"":n,i=t.subType,a=t.type,s=Date.now()+9e5;return window.localStorage.setItem(e.LS_KEY,JSON.stringify({id:o,name:r,subType:i,ttl:s,type:a})),Promise.resolve()}}},{key:"triggerTopicAction",value:function(t){var e=this._util,o=e.apiPath,r=e.id,i=e.name,a=e.shouldSaveToStorage,s=e.subType,c=e.type,u={follow:this._state.actionStatus?"PUT":"DELETE",block:"POST"},l=u[c],f=void 0;return"follow"===c&&(f={types:n({},s,[{id:r}])}),"block"===c&&(f={entities:[{entity_id:r,entity_type:s,score:T[this._state.actionStatus?"block":"unblock"]}]},s===P&&(f.entities[0].entity_name=i)),a?this.saveToStorage():w(o,{cache:0,clientHeaders:{Crumb:t},credentials:"include",method:l,body:JSON.stringify(f)})}},{key:"getCrumb",value:function(){var t=this._util.shouldSaveToStorage,e=this._util.crumb||j;if(e||t)return new Promise(function(t){t(e||"")});var o=this._util,n=o.appId,r=o.actionHost;return w(r+"api/v1/auth/crumb?appId="+n,{cache:0,credentials:"include"}).then(function(t){if(!(j=t.crumb))throw new Error("crumb not found");return j})}},{key:"trigger",value:function(t){var e=this;if(t){var o=t.crumb;o&&(j=o),this._util=f({},this._util,t)}var n=this._util.name,r=this._state.actionStatus;this._state.inProgress=!0,r?this.setActionStatus(!1):this.setActionStatus(!0),this.getCrumb().then(function(t){return e._state.inProgress=!1,e.triggerTopicAction(t)}).then(function(t){var o=t||{},r=o.result,i=void 0===r?{}:r,a=i.success,s=void 0===a?{}:a,c=s.entities,u=void 0===c?[]:c,f=e._util,p=f.id,d=f.type,b="follow"===d&&u.some(function(t){return t.id===p}),y=null!==t&&"object"===(void 0===t?"undefined":l(t));if(!("follow"===d?b:y))throw new Error("action failed");e.didComplete(null,{name:n,type:d})}).catch(function(t){e._state.inProgress=!1,e._state.actionStatus=!e._state.actionStatus,e.setActionStatus(e._state.actionStatus)})}},{key:"handleClick",value:function(t){t.preventDefault(),this._state.inProgress||this.trigger()}}]),e}(g);A.events={click:[["has-click","handleClick"]]},A.LS_KEY=_+"action-storage";var k=A,E=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var o=arguments[e];for(var n in o)Object.prototype.hasOwnProperty.call(o,n)&&(t[n]=o[n])}return t},I=function(){function t(t,e){for(var o=0;o<e.length;o++){var n=e[o];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,o,n){return o&&t(e.prototype,o),n&&t(e,n),e}}(),C=window.wafer,L=C.controllers,x=C.features,H=C.utils,D=L.WaferBaseController,M=H.getConfigFromJSONScriptNode,N=function(t){function e(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},o=t.root,n=void 0===o?document:o,r=t.selector;s(this,e);var i=M(document.getElementById("wafer-action-config")),a=i.actionHost,u=i.appId,l=i.crumb,f=i.shouldSaveToStorage,p=c(this,(e.__proto__||Object.getPrototypeOf(e)).call(this,{root:n,selector:r,props:{actionHost:a,appId:u,crumb:l,shouldSaveToStorage:f,selector:r},WaferClass:k})),d=p;return p.sync(),p._state=E({},p._state,{idInstanceMapping:new Map}),k.prototype.setActionStatus=function(t){var e=this._util.mappingId,o=d._state.idInstanceMapping;o.has(e)||o.set(e,[]),o.get(e).push(this),o.get(e).forEach(function(e){e.statusDidUpdate(t)})},x.localStorage&&setTimeout(function(){p.processStoredAction(i,r)},1),p}return u(e,t),I(e,[{key:"processStoredAction",value:function(t){var e=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"";if(t.shouldProcessState){var o=t.actionHost,n=t.appId,r=t.crumb,i=window.localStorage.getItem(k.LS_KEY);if(i){var a=document.createElement("div"),s={actionHost:o,appId:n,crumb:r,selector:e};try{var c=JSON.parse(i),u=c.id,l=c.name,f=c.ttl,p=void 0===f?0:f,d=c.subType,b=c.type;p&&p>=Date.now()&&b&&d&&u&&(a.setAttribute("data-wf-on","complete:setState:wfAction.entity."+b),new k(a,Object.assign({},s,{id:u,name:l,subType:d,type:b})).trigger(E({},s,{id:u,name:l,subType:d,type:b})))}catch(t){}window.localStorage.removeItem(k.LS_KEY)}}}}]),e}(D),R=N;e.default=new R({selector:".wafer-action"})}})});