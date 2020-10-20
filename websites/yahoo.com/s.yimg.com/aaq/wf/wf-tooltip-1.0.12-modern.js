!function(t,e){"object"==typeof exports&&"object"==typeof module?module.exports=e():"function"==typeof define&&define.amd?define("wafer-tooltip",[],e):"object"==typeof exports?exports["wafer-tooltip"]=e():(t.wafer=t.wafer||{},t.wafer.wafers=t.wafer.wafers||{},t.wafer.wafers["wafer-tooltip"]=e())}("undefined"!=typeof self?self:this,function(){return function(t){function e(i){if(o[i])return o[i].exports;var r=o[i]={i:i,l:!1,exports:{}};return t[i].call(r.exports,r,r.exports,e),r.l=!0,r.exports}var o={};return e.m=t,e.c=o,e.d=function(t,o,i){e.o(t,o)||Object.defineProperty(t,o,{configurable:!1,enumerable:!0,get:i})},e.n=function(t){var o=t&&t.__esModule?function(){return t.default}:function(){return t};return e.d(o,"a",o),o},e.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)},e.p="https://s.yimg.com/aaq/wf/",e(e.s="./src/entry.js")}({"./src/entry.js":function(t,e,o){"use strict";function i(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function r(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function a(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}function s(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}Object.defineProperty(e,"__esModule",{value:!0});var n=function(){function t(t,e){var o=[],i=!0,r=!1,a=void 0;try{for(var s,n=t[Symbol.iterator]();!(i=(s=n.next()).done)&&(o.push(s.value),!e||o.length!==e);i=!0);}catch(t){r=!0,a=t}finally{try{!i&&n.return&&n.return()}finally{if(r)throw a}}return o}return function(e,o){if(Array.isArray(e))return e;if(Symbol.iterator in Object(e))return t(e,o);throw new TypeError("Invalid attempt to destructure non-iterable instance")}}(),l=function(){function t(t,e){for(var o=0;o<e.length;o++){var i=e[o];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(t,i.key,i)}}return function(e,o,i){return o&&t(e.prototype,o),i&&t(e,i),e}}(),u=window.wafer,c=u.constants,f=u.features,d=u.utils,p=c.ATTR_PREFIX,h=c.DISPLAY_BLOCK,y=c.DISPLAY_NONE,v=c.WAFER_DESTROYED,w="has-tooltip-click",g="wafer-tooltip",b="wafer-tooltip-wrapper",m="wafer-tooltip-text",_="wafer-tooltip-close",E=d.convertNodeListToArray,S=["handleTooltipClose"],T=1,C=0,D=3,k=[200,0],L=15,O="wafer-tooltip-template",x="top",A="",j="viewport",P=function(){function t(e){var o=this,r=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},a=r.selector,s=r.successClass;i(this,t),this._util={elem:e,selector:a.replace(".","")};var l=e.getAttribute(p+"local-storage-key");if(!l)return void this.teardown(p+"local-storage-key data attribute is mandatory for element with "+g+" class");var u=e.getAttribute(p+"max-display-count")||D,c=e.getAttribute(p+"reset-every")||L,f=e.getAttribute(p+"template-id")||O,d=e.getAttribute(p+"display-delay")||C,h=e.getAttribute(p+"tooltip-position")||x,v=e.getAttribute(p+"tooltip-text")||A,P=e.getAttribute(p+"trigger")||j,R=e.getAttribute(p+"trigger-offset"),I=R&&R.split(" ")||k,W=n(I,2),N=W[0],B=W[1],Y=e.getAttribute(p+"tooltip-discovered-count")||T;this._util.localStorageKey=l,this._util.maxDisplayCount=u,this._util.resetEvery=c,this._util.discoveredCount=Y;var X=this.getPreviousLocalState;if(this.isResetEveryExceeded(X.lastResetDate)&&this.refreshLastResetDate(),!this.isEligibleToShow)return void this.teardown("Tooltip is not eligible to be shown.");var F=document.getElementById(f);if(!F)return void this.teardown("Cannot find a template with id "+f);if(e.appendChild(F.content.cloneNode(!0)),"top"!==h&&"bottom"!==h)return void this.teardown(p+"tooltip-position must be 'top' or 'bottom'");var K=E(e.getElementsByClassName(b));if(!K.length)return void this.teardown("Cannot find an element with class "+b);var M=K[0];M.setAttribute("data-toolpos",h),M.style.display=y,this._util.divWrapper=M;var V=E(e.getElementsByClassName(m));if(!V.length)return void this.teardown("Cannot find an element with class "+m);V[0].innerHTML=v,this._util.closeButtonElms=E(e.getElementsByClassName(_)),e.classList.contains(_)&&this._util.closeButtonElms.push(e),this._util.closeButtonElms.length&&e.classList.add(w),e.classList.add(s),this._util.offsetX=Number(B),this._util.offsetY=Number(N),this._util.tooltipDisplayDelay=d,this._util.trigger=P,S.forEach(function(t){o[t]=o[t].bind(o)}),window.wafer.base.sync(e)}return l(t,[{key:"teardown",value:function(t){this._util.elem&&this._util.elem.classList.add(v),window.wafer.base.destroy(this._util.elem)}},{key:"destroy",value:function(){var t=this._util.elem;t&&t.classList.add(v),this._util={}}},{key:"showTooltip",value:function(){var t=this,e=this._util,o=e.divWrapper,i=e.tooltipDisplayDelay;if(this.isEligibleToShow&&o&&!this.isTooltipAlreadyVisible){this._util.timeoutId=setTimeout(function(){t._util.timeoutId=void 0,o.style.display=h},i);var r=this.getPreviousLocalState;r.lastDisplayCount++,this.writeToLocalStorage=r}}},{key:"hideTooltip",value:function(){var t=this._util.divWrapper;t&&(t.style.display=y)}},{key:"daysDifference",value:function(t,e){return Math.floor((e-t)/864e5)}},{key:"isResetEveryExceeded",value:function(t){var e=this._util.resetEvery,o=Date.now();return this.daysDifference(t,o)>=e}},{key:"refreshLastResetDate",value:function(){var t=this.getPreviousLocalState;t.lastResetDate=Date.now(),t.lastDisplayCount=0,t.discovered=0,this.writeToLocalStorage=t}},{key:"handleTooltipClose",value:function(t){var e=t.target;if(-1!==this._util.closeButtonElms.indexOf(e)){this._util.divWrapper&&(this._util.divWrapper.style.display=y);var o=this.getPreviousLocalState;o.discovered++,this.writeToLocalStorage=o}}},{key:"config",get:function(){return{offsetX:this._util.offsetX,offsetY:this._util.offsetY,trigger:this._util.trigger}}},{key:"isTooltipAlreadyVisible",get:function(){var t=this._util,e=t.divWrapper,o=t.timeoutId;return e&&e.style.display===h||void 0!==o}},{key:"readFromLocalStorage",get:function(){var t=this._util.localStorageKey,e={};if(f.localStorage)try{e=JSON.parse(window.localStorage.getItem(t))||{}}catch(t){}return e}},{key:"writeToLocalStorage",set:function(t){var e=this._util.localStorageKey;if(f.localStorage)try{window.localStorage.setItem(e,JSON.stringify(t))}catch(t){}}},{key:"getPreviousLocalState",get:function(){var t=this.readFromLocalStorage;return t.discovered=t.discovered||0,t.lastResetDate=t.lastResetDate||Date.now(),t.lastDisplayCount=t.lastDisplayCount||0,t}},{key:"isEligibleToShow",get:function(){var t=this._util,e=t.discoveredCount,o=t.maxDisplayCount,i=this.getPreviousLocalState,r=i.discovered,a=i.lastDisplayCount,s=i.lastResetDate;return!(r>=e||!this.isResetEveryExceeded(s)&&a>=o)}}]),t}();P.events={click:[["has-tooltip-click","handleTooltipClose"]]};var R=P,I=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var o=arguments[e];for(var i in o)Object.prototype.hasOwnProperty.call(o,i)&&(t[i]=o[i])}return t},W=function(){function t(t,e){for(var o=0;o<e.length;o++){var i=e[o];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(t,i.key,i)}}return function(e,o,i){return o&&t(e.prototype,o),i&&t(e,i),e}}(),N=window.wafer.utils,B=N.elementInView,Y=N.throttle,X=window.wafer.base,F=window.wafer.controllers.WaferBaseController,K=function(t){function e(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},o=t.root,i=void 0===o?document:o;r(this,e);var s=e.prototype.configs,n=s.selector,l=s.successClass,u=s.validateDelay,c=void 0===u?25:u,f=a(this,(e.__proto__||Object.getPrototypeOf(e)).call(this,{root:i,selector:n,props:{selector:n,successClass:l},WaferClass:R}));return f._options=I({},f._options,{defaultOffsetY:200,defaultOffsetX:0}),f._validateWithThrottle=Y(function(){f.validate()},c,f),f.sync(),f}return s(e,t),W(e,[{key:"handleScroll",value:function(){this._validateWithThrottle()}},{key:"handleResize",value:function(){this._validateWithThrottle()}},{key:"willValidate",value:function(t){var e=this._state.elementInstances;t.forEach(function(t){var o=e.get(t),i=o.instance,r=i.config,a=r.trigger,s=r.offsetX,n=r.offsetY;switch(a){case"onLoad":i.renderTooltip();break;case"viewport":default:B(t,{offsetX:s,offsetY:n},X.viewport)?i.showTooltip():i.hideTooltip()}})}}]),e}(F);K.prototype.configs={selector:".wafer-tooltip",successClass:"wafer-tooltip-done"};var M=K;e.default=new M({selector:M.prototype.configs.selector})}})});