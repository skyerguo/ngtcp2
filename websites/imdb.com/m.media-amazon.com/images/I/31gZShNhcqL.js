(window.webpackJsonpBoomer=window.webpackJsonpBoomer||[]).push([["imdb.IMDbStreamingPicksReactFeature"],{"7LKvjz8Hn4":function(e,t,n){e.exports={streamingPicksTabs:"p8LLdvb7XDlJqXAWIBltB",tabDescription:"_1ZJCMd7QvtDv9gNz8XcVLT",streamingPicksPlaceholder:"_3jDsp0SC8JqCoh4_NpukHU","ipc-tabs__indicator":"CTdPZ3jyZqOOVQjur4ucU","ipc-rating-star":"_2870SFLBW-AKyPRbCYPTgm","ipc-icon--movie":"ATxjg3s1B8cfMEVKL9IuH","ipc-watchlist-ribbon":"_24wCgvvoRiqOLktaIs-gdq","tab-description":"lov0IyGhH4koI5KgcBwZh"}},EMyApEhX8S:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var i=n("WSs4/Y+dbX");t.StreamingPicksFeature=i.Feature,t.default=i.Feature},"IKO8+RQZHmZ":function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var i=n("qRaHSO6Ju0s");t.headTags={loadTitleBegin:i.csmWidgetBeginScript("LoadTitle"),loadTitleEnd:i.csmWidgetEndScript("LoadTitle"),loadIconsBegin:i.csmWidgetBeginScript("LoadIcons"),loadIconsEnd:i.csmWidgetEndScript("LoadIcons"),loadCssBegin:i.csmWidgetBeginScript("LoadCSS"),loadCssEnd:i.csmWidgetEndScript("LoadCSS"),loadHeaderJsBegin:i.csmWidgetBeginScript("LoadHeaderJS"),loadHeaderJsEnd:i.csmWidgetEndScript("LoadHeaderJS")}},"WSs4/Y+dbX":function(e,t,n){"use strict";var i,r=this&&this.__extends||(i=function(e,t){return(i=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var n in t)t.hasOwnProperty(n)&&(e[n]=t[n])})(e,t)},function(e,t){function n(){this.constructor=e}i(e,t),e.prototype=null===t?Object.create(t):(n.prototype=t.prototype,new n)}),a=this&&this.__assign||function(){return(a=Object.assign||function(e){for(var t,n=1,i=arguments.length;n<i;n++)for(var r in t=arguments[n])Object.prototype.hasOwnProperty.call(t,r)&&(e[r]=t[r]);return e}).apply(this,arguments)};Object.defineProperty(t,"__esModule",{value:!0});var s=n("LDoPTt+kJa"),o=n("CTbtN8TX6q"),c=n("l42YtCfhhb"),d=n("ekp6onNDDg"),u=n("qDO/KKoIw4"),l=n("E1DRvlOYYt"),p=n("XE6t8R6oPQO"),g=n("Kkip5aHMh7"),f=n("2KSaVHM2Nk"),T=n("7LKvjz8Hn4"),b=function(e){function t(t){var n=e.call(this,t)||this;n.depthQueue=[],n.getTitleCardView=function(e,t){var i=n.props.weblabExperiments||n.context.getWeblabExperiments(),r="T1"===o(i,"IMDB_HOMEPAGE_TRAILERS_267206","C"),a="T1"===o(i,"IMDB_267239","C");return{href:e.titlePageLink,id:e.titleId,imdbRating:e.aggregateRating,userRating:e.userRating,titleRatingCanVote:e.titleRatingCanVote,name:e.displayTitle,trailerLink:e.trailerLink,posterImage:n.getPosterImageView(e),miniBuyBox:{miniBuyBoxProps:e.miniBuyBox},watchableTitleCardMetricsContext:e.watchableTitleCardMetricsContext,trailerWeblabEnabled:r,ratingWeblabEnabled:a}},n.getPosterImageView=function(e){return{imageModel:e.poster,imageType:e.titleType}};var i=t.StreamingPicksModel.tabs;return n.state={selectedTabIndex:0,tabs:i},n.sendDepthMetrics=c(n.sendDepthMetrics,5e3),n}return r(t,e),t.prototype.render=function(){var e=this.state,t=e.tabs,n=e.lazyLoaded;return t?s.createElement(s.Fragment,null,s.createElement("div",{className:g.default(this.props.className,"streaming-picks")},s.createElement("div",{className:T.streamingPicksTabs},s.createElement(u.Tabs,{className:"tabs",tabs:this.renderTabs(t),onChange:this.onChangeTabs.bind(this,t),key:"tabs"})),this.renderTabDescription(t[this.state.selectedTabIndex]),this.renderTabContents(t[this.state.selectedTabIndex])),n&&p.featureEnd("StreamingPicksLazyLoad")):this.renderPlaceholder()},t.prototype.onChangeTabs=function(e,t){this.submitMetrics(e[t].refTag),this.setState({selectedTabIndex:Number(t)})},t.prototype.renderTabs=function(e){return e.map(function(e,t){return{id:String(t),label:e.displayName}})},t.prototype.renderTabDescription=function(e){return s.createElement("p",{className:T.tabDescription},e.description)},t.prototype.sendDepthMetrics=function(){var e=this.state.tabs,n=Math.max.apply(Math,this.depthQueue);if(e){var i={ref_:e[this.state.selectedTabIndex].refTag,pageAction:"depth-"+n,pt:t.METRICS_CONTEXT.PAGE_TYPE,spt:t.METRICS_CONTEXT.SUB_PAGE_TYPE,ht:t.METRICS_CONTEXT.HIT_TYPE};d.default({method:"POST",url:t.METRICS_URL,headers:{"Content-type":"application/x-www-form-urlencoded"},data:this.encodeParameters(i)}).catch(function(e){console.error("Failed to submit scroll depth metric.",e)})}this.depthQueue.splice(0,this.depthQueue.length)},t.prototype.visibilityChange=function(e){this.depthQueue.push(e),this.sendDepthMetrics()},t.prototype.renderTabContents=function(e){var t=this;return s.createElement(u.Shoveler,{wraps:!1,key:this.state.selectedTabIndex+"-"+e.providerId},e.tabContents.map(function(e,n){return s.createElement(l.default,a({key:e.titleId+"-"+n},t.getTitleCardView(e,n+1),{lazyRender:n>=6,visibilityChange:function(){return t.visibilityChange(n)}}))}))},t.prototype.submitMetrics=function(e){var n={ref_:e,pageAction:t.METRICS_CONTEXT.PAGE_ACTION,pt:t.METRICS_CONTEXT.PAGE_TYPE,spt:t.METRICS_CONTEXT.SUB_PAGE_TYPE,ht:t.METRICS_CONTEXT.HIT_TYPE};d.default({method:"POST",url:t.METRICS_URL,headers:{"Content-type":"application/x-www-form-urlencoded"},data:this.encodeParameters(n)}).catch(function(e){console.error("Failed to submit tab-select metric.",e)})},t.prototype.encodeParameters=function(e){return void 0===e&&(e={}),Object.keys(e).map(function(t){return encodeURIComponent(t)+"="+encodeURIComponent(e[t])}).join("&")},t.prototype.createPlaceholderItem=function(e){return{miniBuyBox:{titleId:e,providerId:"",displayText:"",linkUrl:"",baseRef:"",baseAssociateTag:"",isOffsiteLink:!1},titleType:"movie",titlePageLink:"",displayTitle:"",aggregateRating:10,titleRatingCanVote:!1,titleId:"",watchableTitleCardMetricsContext:{watchlistButtonMetricsContext:{pageType:"home",subPageType:"main",refTag:""},watchlistRibbonMetricsContext:{pageType:"home",subPageType:"main",refTag:""}}}},t.prototype.renderPlaceholder=function(){for(var e=[],t=0;t<6;t++)e.push(this.createPlaceholderItem("placeholder-"+t));var n={description:"",providerId:"",displayName:"",refTag:"",tabContents:e};return s.createElement(s.Fragment,{key:"placeholder"},s.createElement("div",{className:g.default(this.props.className,"streaming-picks",T.streamingPicksPlaceholder)},s.createElement("div",{className:T.streamingPicksTabs},s.createElement(u.Tabs,{className:T.tabs,tabs:[{id:"placeholder",label:n.displayName}],key:"placeholder"})),this.renderTabDescription(n),this.renderTabContents(n)))},t.contextType=f.SlotContext,t.METRICS_URL="/tr/",t.METRICS_CONTEXT={PAGE_ACTION:"tab-select",PAGE_TYPE:"home",SUB_PAGE_TYPE:"main",HIT_TYPE:"actionOnly"},t}(s.PureComponent);t.Feature=b,t.default=b},XE6t8R6oPQO:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var i=n("Y33WuQsxQYV");t.bodyTags=i.bodyTags,t.featureBegin=i.featureBegin,t.featureEnd=i.featureEnd;var r=n("IKO8+RQZHmZ");t.headTags=r.headTags},Y33WuQsxQYV:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var i=n("LDoPTt+kJa"),r=n("qRaHSO6Ju0s"),a="if (typeof uet == 'function') { uet(\"af\");}",s="if (typeof uet == 'function') { uet(\"bb\");}",o="if (typeof uet == 'function') { uet(\"be\");}",c="if (typeof uet == 'function') { uet(\"ns\");}",d="if (typeof uet == 'function') { uet(\"ne\");}";function u(e){return i.createElement("script",{dangerouslySetInnerHTML:{__html:e}})}function l(e){return r.csmWidgetBeginString(e)}function p(e){return r.csmWidgetEndString(e)}t.buildScript=u,t.featureBeginString=l,t.featureEndString=p,t.bodyTags={atf:u(a),bodyStart:u(s),bodyEnd:u(o),navBarStart:u(c),navBarEnd:u(d)},t.featureBegin=function(e){return i.createElement("script",{dangerouslySetInnerHTML:{__html:l(e)}})},t.featureEnd=function(e){return p(e).map(function(e){return i.createElement("script",{dangerouslySetInnerHTML:{__html:e}})})}},qRaHSO6Ju0s:function(e,t,n){"use strict";function i(e,t){return"if (typeof uet == 'function') {\n                uet(\""+e+'", "'+t+'", {wb: 1});\n            }'}function r(e){return'if (typeof uex == \'function\') {\n                uex("ld", "'+e+'", {wb: 1});\n            }'}Object.defineProperty(t,"__esModule",{value:!0}),t.csmWidgetBeginScript=function(e){return"\n        <script>\n            "+i("bb",e)+"\n        <\/script>"},t.csmWidgetEndScript=function(e){return"\n        <script>\n            "+i("be",e)+"\n        <\/script>\n        <script>\n            "+r(e)+"\n        <\/script>"},t.csmWidgetBeginString=function(e){return i("bb",e)},t.csmWidgetEndString=function(e){return[i("be",e),r(e)]}}}]);